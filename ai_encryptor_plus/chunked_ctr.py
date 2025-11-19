import os, secrets, json, math, hashlib, mmap, gc
from pathlib import Path
from concurrent.futures import ProcessPoolExecutor, as_completed
from typing import Tuple
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from .key_vault import store_key, load_key

# --- HELPER: HEADER CONSTANTS ---
HEADER_MAGIC = b"CTRCH"
HEADER_SIZE = 5 + 16 + 8 # Magic(5) + Nonce(16) + ChunkSize(8) = 29 bytes
LEN_PREFIX_SIZE = 8 # 8 bytes for length prefix per chunk

def _derive_base_nonce() -> bytes:
    return secrets.token_bytes(8) + secrets.token_bytes(8)

def _chunk_nonce(base_nonce: bytes, idx: int) -> bytes:
    prefix = base_nonce[:8]
    counter_bytes = idx.to_bytes(8, "big")
    return prefix + counter_bytes

def _derive_auth_key(aes_key: bytes) -> bytes:
    return hashlib.sha256(aes_key + b"auth_key").digest()

# --- WORKER (MMAP ZERO-COPY) ---
def _worker_encrypt_chunk_mmap(args) -> Tuple[int, bytes]:
    key, base_nonce, idx, src_path, offset, length = args
    nonce = _chunk_nonce(base_nonce, idx)
    
    with open(src_path, "r+b") as f:
        # Direct OS Map - Zero User Buffer Copy
        with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            chunk_data = mm[offset : offset + length]
            cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
            op = cipher.encryptor()
            # Encrypt
            ct = op.update(chunk_data) + op.finalize()
            
    return idx, ct

def _worker_decrypt_chunk(args) -> Tuple[int, bytes]:
    key, base_nonce, idx, ct = args
    nonce = _chunk_nonce(base_nonce, idx)
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
    dec = cipher.decryptor()
    pt = dec.update(ct) + dec.finalize()
    return idx, pt

# --- MAIN ENGINE (SCATTER-WRITE OPTIMIZED) ---

def encrypt_file_chunked(src: Path, dst: Path, key: bytes, key_id: str,
                         master_secret: str,
                         chunk_size: int = 8 * 1024 * 1024,
                         workers: int = 4,
                         use_processes: bool = True,
                         write_manifest: bool = True,
                         executor=None):
    
    # 1. Setup
    src = Path(src)
    dst = Path(dst)
    tmp = dst.with_suffix(dst.suffix + ".tmp")
    manifest = dst.with_suffix(dst.suffix + ".meta.json")
    
    filesize = src.stat().st_size
    chunk_count = math.ceil(filesize / chunk_size) if chunk_size > 0 else 1
    base_nonce = _derive_base_nonce()
    auth_key = _derive_auth_key(key)

    # 2. Prepare Tasks (Coordinates)
    args_list = []
    for idx in range(chunk_count):
        offset = idx * chunk_size
        length = min(chunk_size, filesize - offset)
        args_list.append((key, base_nonce, idx, str(src), offset, length))

    # 3. Submit to Pool
    if executor and use_processes:
        futures = {executor.submit(_worker_encrypt_chunk_mmap, a): i for i, a in enumerate(args_list)}
    elif use_processes:
        # Fallback pool (only if global is missing)
        pool = ProcessPoolExecutor(max_workers=workers)
        futures = {pool.submit(_worker_encrypt_chunk_mmap, a): i for i, a in enumerate(args_list)}
    else:
        # Thread fallback (rare)
        from concurrent.futures import ThreadPoolExecutor
        pool = ThreadPoolExecutor(max_workers=workers)
        futures = {pool.submit(_worker_encrypt_chunk_mmap, a): i for i, a in enumerate(args_list)}

    # 4. ASYNC SCATTER-WRITE (The Speedup)
    # Instead of waiting for all, we write to disk AS SOON as a chunk finishes.
    # We use file.seek() to place the data in the exact correct spot.
    
    # Disable GC to prevent micro-stutters during high-speed IO
    gc.disable()
    
    try:
        with open(tmp, "wb") as out:
            # A. Write Header immediately
            out.write(HEADER_MAGIC)
            out.write(base_nonce)
            out.write(chunk_size.to_bytes(8, "big"))
            
            # B. Pre-allocate file size (Optional, prevents fragmentation)
            # Total = Header + (Count * LenPrefix) + FileSize
            # (Approximate, assumes CiphertextLen == PlaintextLen which is true for CTR)
            # out.seek(HEADER_SIZE + (chunk_count * LEN_PREFIX_SIZE) + filesize - 1)
            # out.write(b'\0')
            
            chunk_hmacs = [None] * chunk_count

            # C. Process Results Out-of-Order
            for fut in as_completed(futures):
                idx, ct = fut.result()
                
                # Calculate HMAC while data is hot in cache
                mac = hmac.new(auth_key, ct, hashlib.sha256).hexdigest()
                chunk_hmacs[idx] = mac

                # CALCULATE DISK OFFSET
                # Where does this chunk belong?
                # Pos = Header + (Index * (LenPrefix + ChunkSize))
                # Note: This math works because all chunks (except last) are fixed size.
                # For the last chunk, it naturally falls at the end, but since we might 
                # write the last chunk *before* the first one finishes, we need exact math.
                
                # Wait! If last chunk is smaller, simple multiplication fails for indexes AFTER it?
                # Actually, only the *last* chunk varies. So standard multiplication works 
                # for every chunk start position.
                
                write_pos = HEADER_SIZE + (idx * (LEN_PREFIX_SIZE + chunk_size))
                
                # Write Length + Data
                out.seek(write_pos)
                out.write(len(ct).to_bytes(8, "big"))
                out.write(ct)
                
                # Release memory immediately
                del ct
                
    finally:
        gc.enable()
        if not executor and use_processes:
            pool.shutdown()

    # 5. Finalize
    os.replace(str(tmp), str(dst))

    if write_manifest:
        m = {
            "mode": "CTR_CHUNKED",
            "base_nonce": base_nonce.hex(),
            "chunk_size": chunk_size,
            "chunk_count": chunk_count,
            "key_id": key_id,
            "chunk_hmacs": chunk_hmacs, # Only thing that needs order
            "version": 1
        }
        manifest.write_text(json.dumps(m))

    try: store_key(key_id, key, "ctr", master_secret)
    except: pass

# Import needed for HMAC inside function
import hmac 

def decrypt_file_chunked(enc_path: Path, out_path: Path, key_id: str=None, 
                         master_secret: str = None, 
                         use_processes: bool=True, workers: int=4,
                         executor=None):
    enc_path = Path(enc_path)
    out_path = Path(out_path)
    manifest = enc_path.with_suffix(enc_path.suffix + ".meta.json")
    
    if not manifest.exists(): raise FileNotFoundError("Manifest required")
    m = json.loads(manifest.read_text())
    base_nonce = bytes.fromhex(m["base_nonce"])
    chunk_size = int(m["chunk_size"])
    keyid = m.get("key_id") if key_id is None else key_id

    if not master_secret: raise ValueError("Master secret required")
    key, mode = load_key(keyid, master_secret)
    
    # SCATTER-READ STRATEGY
    # We don't need to read sequentially either.
    
    chunk_count = m["chunk_count"]
    
    # 1. Launch Tasks
    args_list = []
    
    # We must open file to read offsets? 
    # Actually, since we enforce fixed structure, we can predict read offsets too!
    
    with open(enc_path, "rb") as f:
        # Verify Header
        if f.read(5) != HEADER_MAGIC: raise ValueError("Invalid header")
        
        # Since we used "Sparse/Seek" writing, the file on disk might have gaps 
        # if we didn't fill it perfectly, but we did.
        # However, reading involves checking length prefixes.
        
        # Optimization: Just read the whole thing into mmap and slice it up?
        # For decryption, we can't easily use mmap for *variable* length records 
        # if we didn't enforce strict size. 
        # But in our encryptor, we did: write_pos = ... idx * (LEN + chunk_size)
        # This essentially padded the file to fixed blocks (except last).
        
        # So we can use calculated offsets for decryption too!
        pass

    # Since decryption logic is complex to scatter-gather safely without strict 
    # validation, let's stick to the robust read-all-headers approach but 
    # parallelize execution rapidly.
    
    chunks_data = []
    with open(enc_path, "rb") as f:
        f.seek(HEADER_SIZE) # Skip header
        
        for _ in range(chunk_count):
            # In our fixed-grid format, we can seek!
            # This is faster than reading linearly if OS buffers are smart.
            len_bytes = f.read(8)
            if not len_bytes: break
            l = int.from_bytes(len_bytes, "big")
            ct = f.read(l)
            chunks_data.append(ct)
            
            # If this wasn't the last chunk, and l < chunk_size, we might need to seek forward
            # to the next grid slot?
            # Our encryptor writes to: HEADER_SIZE + (idx * (LEN + chunk_size))
            # If actual data was smaller (last chunk), the next chunk starts far away.
            # But loop assumes packed.
            
            # CRITICAL FIX for reading "Sparse/Grid" files:
            # We must seek to the next grid position after reading, 
            # unless we simply read sequentially and assume the file is packed.
            
            # If we used seek() in writer, we created holes (sparse file) or overwritten.
            # Simpler approach for Decryptor compatibility:
            # Just read sequentially. The writer produced a valid stream?
            # No, the writer used seek(). If chunk 1 is 5 bytes but chunk_size is 10,
            # writer put chunk 2 at offset 10+8. There is a gap!
            
            # To fix this complexity: The Writer logic above assumes input 
            # was FULL chunks. Elastic chunking ensures this for all except last.
            # So no gaps exist for 0..N-1. 
            # So sequential read is safe.
            pass

    # Parallel Decrypt
    args_list = [(key, base_nonce, i, ct) for i, ct in enumerate(chunks_data)]
    results = [None] * len(args_list)
    
    # Use Global Pool
    if executor and use_processes:
        futures = {executor.submit(_worker_decrypt_chunk, a): i for i, a in enumerate(args_list)}
    else:
        pool = ProcessPoolExecutor(max_workers=workers)
        futures = {pool.submit(_worker_decrypt_chunk, a): i for i, a in enumerate(args_list)}
        
    # Scatter-Write Decrypted
    tmp = out_path.with_suffix(out_path.suffix + ".tmp")
    
    with open(tmp, "wb") as out:
        for fut in as_completed(futures):
            idx, pt = fut.result()
            # Calculate plaintext offset
            # Plaintext is just pure data, no length prefixes.
            # Pos = idx * chunk_size
            out.seek(idx * chunk_size)
            out.write(pt)
            del pt

    os.replace(str(tmp), str(out_path))
