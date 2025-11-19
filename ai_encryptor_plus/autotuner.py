# ai_encryptor_plus/autotuner.py
import os, time, hashlib
from typing import Tuple, List
import multiprocessing
import concurrent.futures

def cpu_count():
    try:
        return multiprocessing.cpu_count()
    except Exception:
        return 1

# --- OS REQUIREMENT: Top-level function for Pickling ---
# Local functions inside _trial() cannot be pickled on Windows when using Processes.
def _worker_task(data_chunk: bytes) -> bool:
    # Simulate CPU-heavy work (SHA256 is a good proxy for AES)
    hashlib.sha256(data_chunk).digest()
    return True

def _trial(chunk_size: int, workers: int, sample_mb: int = 16) -> float:
    # Create random data buffer
    # Note: For the benchmark, we still pass data via IPC (Pickle) rather than mmap.
    # This actually helps penalize "Too Many Workers" correctly, because 
    # it simulates the overhead of coordinating many heavy processes.
    data = os.urandom(sample_mb * 1024 * 1024)
    
    # Slicing
    parts = [data[i:i+chunk_size] for i in range(0, len(data), chunk_size)]
    
    t0 = time.time()
    
    # --- OS CHANGE: Use ProcessPoolExecutor ---
    # This measures the cost of spawning processes + context switching.
    # If 16 workers take too long to start, this benchmark will now catch it!
    with concurrent.futures.ProcessPoolExecutor(max_workers=workers) as ex:
        # We use list() to force execution and wait for all results
        list(ex.map(_worker_task, parts))
        
    t1 = time.time()
    elapsed = t1 - t0
    
    # Return MB/s
    throughput = len(data) / (1024*1024) / max(1e-6, elapsed)
    return throughput

def tune_short(trial_seconds: int = 3, candidate_chunks: List[int] = None) -> dict:
    # Benchmarking different configurations
    if candidate_chunks is None:
        candidate_chunks = [1*1024*1024, 4*1024*1024, 8*1024*1024, 16*1024*1024]
    
    cpus = cpu_count()
    # We test: 1 worker, Half Cores, All Cores, and 1.5x Cores (to see if oversubscribing helps)
    candidate_workers = sorted(list(set([1, max(1, cpus//2), cpus, int(cpus * 1.5)])))
    
    results = {}
    print(f"  [AutoTuner] Benchmarking {len(candidate_chunks)} chunk sizes across {candidate_workers} worker counts...")
    
    for c in candidate_chunks:
        for w in candidate_workers:
            try:
                perf = _trial(c, w)
                results[(c, w)] = perf
                # Optional: Debug print to see scores real-time
                # print(f"    Chunk {c//1024//1024}MB | Workers {w} -> {perf:.2f} MB/s")
            except Exception as e:
                # print(f"    Failed {c}, {w}: {e}")
                results[(c, w)] = 0.0
                
    # Pick the winner
    best = max(results.items(), key=lambda kv: kv[1])
    best_chunk, best_workers = best[0]
    
    return {"best_chunk": best_chunk, "best_workers": best_workers, "all": results}
