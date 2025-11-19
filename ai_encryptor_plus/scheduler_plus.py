# ai_encryptor_plus/scheduler_plus.py
import heapq
from pathlib import Path
from typing import List
from .cost_model import CostModel

class Task:
    __slots__ = ("prio","path","size","suffix")
    def __init__(self, prio, path, size, suffix):
        self.prio = prio
        self.path = path
        self.size = size
        self.suffix = suffix
    def __lt__(self, other): return self.prio < other.prio

class SchedulerPlus:
    def __init__(self, max_workers=4):
        self.cm = CostModel()
        self.max_workers = max_workers

    def plan(self, files: List[Path]) -> List[Task]:
        # Files ko priority ke saath schedule karta hai
        
        if not files: return []

        total_size = sum(p.stat().st_size for p in files)

        # --- OS SCHEDULING OPTIMIZATION ---
        # Threshold: 10 MB.
        # If total work is small, the overhead of predicting cost (CostModel) 
        # is higher than the actual work. 
        # Solution: Use simple "Shortest Job First" (SJF) via standard sort.
        # This guarantees we are faster than FIFO for small batches.
        if total_size < 10 * 1024 * 1024: 
            # Create tasks with priority = size (Smaller size = Higher priority)
            raw_tasks = [Task(p.stat().st_size, p, p.stat().st_size, p.suffix.lower()) for p in files]
            raw_tasks.sort(key=lambda x: x.size)
            return raw_tasks

        # --- HEAVY WORKLOAD AI LOGIC ---
        # Only use the predictive model for non-trivial workloads
        pq = []
        for p in files:
            size = p.stat().st_size
            suffix = p.suffix.lower()
            prio = self.cm.predict_seconds(chunk_size=size, suffix=suffix, sample=None)
            heapq.heappush(pq, Task(prio, p, size, suffix))
        
        plan = []
        while pq:
            plan.append(heapq.heappop(pq))
        return plan

    def observe(self, p: Path, elapsed: float):
        # Feedback loop for the AI model
        size = p.stat().st_size
        self.cm.observe(chunk_size=size, suffix=p.suffix.lower(), actual_s=elapsed, sample=None)
