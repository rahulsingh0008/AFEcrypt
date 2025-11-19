import argparse, os, time, hashlib, json, math
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed, ProcessPoolExecutor
from typing import Tuple, List

from .config import DEFAULT_CHUNK_MB
from .encryptor import gen_key, encrypt_stream
from .scheduler_plus import SchedulerPlus, Task 
from .packager import make_archive
from .decryptor import decrypt_file
from .chunked_ctr import encrypt_file_chunked, decrypt_file_chunked

def _calculate_elastic_chunk_size(file_size: int, workers: int) -> int:
    if file_size == 0: return 1024 * 1024
    target_chunk_count = workers * 4
    ideal_size = file_size // target_chunk_count
    MIN_CHUNK = 1 * 1024 * 1024
    MAX_CHUNK = 64 * 1024 * 1024  
    if ideal_size < MIN_CHUNK: ideal_size = MIN_CHUNK
    if ideal_size > MAX_CHUNK: ideal_size = MAX_CHUNK
    ideal_size = (ideal_size // 16) * 16
    if ideal_size == 0: ideal_size = 16
    return int(ideal_size)

def run_encrypt(in_dir: str, out_dir: str, mode: str, master_secret: str,
                workers: int=4, 
                use_processes: bool=False, 
                policy: str='priority', 
                chunk_size: int = (DEFAULT_CHUNK_MB * 1024 * 1024),
                scheduler=None, 
                executor=None
                ) -> Tuple[float, str]: 
    
    t_start = time.time() 
    in_dir = Path(in_dir)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    
    files = [p for p in in_dir.rglob("*") if p.is_file()]
    if not files: return 0.0, ""

    # --- PLAN ---
    current_scheduler = scheduler if scheduler else SchedulerPlus(max_workers=workers)

    if policy == 'priority':
        plan = current_scheduler.plan(files) 
    else:
        plan = [Task(prio=idx, path=p, size=p.stat().st_size, suffix=p.suffix.lower()) 
                for idx, p in enumerate(files)]

    in_dir_hash = hashlib.sha256(str(in_dir).encode()).hexdigest()[:16]
    key_id = f"{in_dir_hash}-{mode}-{int(t_start)}"
    key = gen_key() 
    
    # Threshold lowered to 16MB because Elastic Chunking is efficient
    HEAVY_THRESHOLD = 16 * 1024 * 1024 
    
    big_tasks = []
    small_tasks = []
    
    for t in plan:
        if t.size >= HEAVY_THRESHOLD and mode.lower() == 'ctr':
            big_tasks.append(t)
        else:
            small_tasks.append(t)

    # --- 1. SMALL TASKS STRATEGY ---
    if small_tasks:
        # OPTIMIZATION A: The "Inline" Shortcut
        # If there is only 1 small file, don't waste time creating a ThreadPool.
        # Just run it. This saves 5-10ms of overhead.
        if len(small_tasks) == 1:
            task = small_tasks[0]
            p = task.path
            rel = p.relative_to(in_dir)
            outp = out_dir / rel.with_suffix(rel.suffix + ".enc")
            outp.parent.mkdir(parents=True, exist_ok=True)
            try:
                encrypt_stream(str(p), str(outp), mode, key_id, key, master_secret)
                current_scheduler.observe(p, 0.001) # Minimal cost
            except Exception as e:
                print(f"Error {p}: {e}")
        
        # OPTIMIZATION B: The "Hyper-Threaded" Batch
        # For multiple small files, we are I/O bound (waiting for disk).
        # We increase workers to 4x to keep the disk queue full.
        else:
            with ThreadPoolExecutor(max_workers=workers * 4) as tex:
                futures = {}
                for task in small_tasks:
                    p = task.path
                    rel = p.relative_to(in_dir)
                    outp = out_dir / rel.with_suffix(rel.suffix + ".enc")
                    outp.parent.mkdir(parents=True, exist_ok=True)
                    
                    f = tex.submit(encrypt_stream, str(p), str(outp), mode, key_id, key, master_secret)
                    futures[f] = p

                for f in as_completed(futures):
                    p = futures[f]
                    try: 
                        f.result()
                        current_scheduler.observe(p, 0.01) 
                    except Exception as e: 
                        print(f"Error {p}: {e}")

    # --- 2. LARGE TASKS STRATEGY (ProcessPool + Elastic Chunking) ---
    if big_tasks:
        for task in big_tasks:
            p = task.path
            rel = p.relative_to(in_dir)
            outp = out_dir / rel.with_suffix(rel.suffix + ".enc")
            outp.parent.mkdir(parents=True, exist_ok=True)
            
            # Elastic Chunking
            elastic_chunk = _calculate_elastic_chunk_size(task.size, workers)
            
            t0 = time.time()
            try:
                encrypt_file_chunked(
                    src=p, dst=outp, key=key, key_id=key_id,
                    master_secret=master_secret,
                    chunk_size=elastic_chunk, 
                    workers=workers,
                    use_processes=True,
                    executor=executor
                )
                elapsed = time.time() - t0
                current_scheduler.observe(p, elapsed)
            except Exception as e:
                print(f"Error Chunked {p}: {e}")

    t_end_encryption = time.time()
    archive_name = f"encrypted_{policy}_{int(t_start)}.zip"
    arch_path = make_archive(out_dir, archive_name=archive_name)
    
    return (t_end_encryption - t_start), arch_path

# (run_decrypt remains unchanged from previous version, assuming you have it)
def run_decrypt(in_dir: str, out_dir: str, master_secret: str, workers: int=4, 
                use_processes: bool=False, executor=None):
    in_dir = Path(in_dir)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    files = [p for p in in_dir.rglob("*.enc") if p.is_file()]
    if not files:
        payload = in_dir / "payload"
        if payload.exists(): files = [p for p in payload.rglob("*.enc") if p.is_file()]
    
    if executor and use_processes:
        futures = []
        for p in files:
            _submit_decrypt_task(p, in_dir, out_dir, master_secret, workers, use_processes, futures, executor)
        for f in as_completed(futures):
            try: f.result()
            except: pass
    else:
        exec_cls = ProcessPoolExecutor if use_processes else ThreadPoolExecutor
        with exec_cls(max_workers=workers) as ex:
            futures = []
            for p in files:
                _submit_decrypt_task(p, in_dir, out_dir, master_secret, workers, use_processes, futures, ex)
            for f in as_completed(futures):
                try: f.result()
                except: pass

def _submit_decrypt_task(p, in_dir, out_dir, master_secret, workers, use_processes, futures_list, executor):
    rel = p.relative_to(in_dir)
    outp_name = ".".join(rel.name.split('.')[:-1]) if '.enc' in rel.name else rel.name + ".dec"
    meta = p.with_suffix(p.suffix + ".meta.json")
    key_id, is_chunked = None, False
    if meta.exists():
        try:
            md = json.loads(meta.read_text())
            if "src" in md: outp_name = md["src"]
            key_id = md.get("key_id")
            is_chunked = md.get("mode") == "CTR_CHUNKED"
        except: pass
    outp = out_dir / rel.parent / outp_name
    outp.parent.mkdir(parents=True, exist_ok=True)
    if is_chunked:
        futures_list.append(executor.submit(decrypt_file_chunked, p, outp, key_id, master_secret, use_processes, workers, executor))
    else:
        futures_list.append(executor.submit(decrypt_file, str(p), str(outp), key_id, master_secret))
