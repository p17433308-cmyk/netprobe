"""Multi-core parallel job scheduling for fuzzing campaigns."""

from __future__ import annotations

import os
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable


@dataclass
class Job:
    job_id: str
    target: str
    pcap_path: Path
    decode_as: str | None = None
    priority: int = 0


@dataclass
class JobResult:
    job_id: str
    success: bool
    crashed: bool = False
    duration: float = 0.0
    error: str | None = None


class ParallelScheduler:
    """Schedule fuzzing jobs across multiple CPU cores."""

    def __init__(self, max_workers: int | None = None, timeout_per_job: float = 30.0):
        self.max_workers = max_workers or max(1, os.cpu_count() - 1)
        self.timeout = timeout_per_job
        self.completed = 0
        self.crashes_found = 0

    def run_batch(self, jobs: list[Job], execute_fn: Callable[[Job], JobResult]) -> list[JobResult]:
        results = []
        jobs_sorted = sorted(jobs, key=lambda j: j.priority, reverse=True)

        with ProcessPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {
                executor.submit(execute_fn, job): job
                for job in jobs_sorted
            }

            for future in as_completed(futures):
                job = futures[future]
                try:
                    result = future.result(timeout=self.timeout)
                    results.append(result)
                    self.completed += 1
                    if result.crashed:
                        self.crashes_found += 1
                except Exception as e:
                    results.append(JobResult(
                        job_id=job.job_id,
                        success=False,
                        error=str(e),
                    ))

        return results

    def stats(self) -> dict:
        return {
            "completed": self.completed,
            "crashes_found": self.crashes_found,
            "workers": self.max_workers,
        }
