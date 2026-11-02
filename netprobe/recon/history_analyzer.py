"""Git history risk analysis — recently changed parsers = higher risk."""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass
class FileRisk:
    file_path: str
    commit_count: int
    recent_commits: int
    authors: int
    has_security_fixes: bool
    risk_score: float


class HistoryAnalyzer:
    """Analyze git history to identify high-risk parser files."""

    SECURITY_KEYWORDS = [
        "cve", "security", "vulnerability", "overflow", "crash",
        "asan", "ubsan", "oob", "use-after-free", "double-free",
        "null deref", "heap", "stack", "bounds", "fix", "patch",
    ]

    def analyze(self, repo_path: str | Path, file_glob: str = "epan/dissectors/packet-*.c",
                days: int = 180) -> list[FileRisk]:
        repo = Path(repo_path)
        results = []

        try:
            file_list = subprocess.run(
                ["git", "ls-files", file_glob],
                cwd=repo, capture_output=True, text=True, timeout=30,
            )
            files = file_list.stdout.strip().split("\n")
        except Exception:
            return []

        for f in files:
            if not f.strip():
                continue
            risk = self._analyze_file(repo, f, days)
            if risk:
                results.append(risk)

        results.sort(key=lambda r: r.risk_score, reverse=True)
        return results

    def _analyze_file(self, repo: Path, file_path: str, days: int) -> FileRisk | None:
        try:
            log = subprocess.run(
                ["git", "log", f"--since={days} days ago", "--format=%H|%ae|%s",
                 "--", file_path],
                cwd=repo, capture_output=True, text=True, timeout=15,
            )
            total_log = subprocess.run(
                ["git", "log", "--format=%H", "--", file_path],
                cwd=repo, capture_output=True, text=True, timeout=15,
            )
        except Exception:
            return None

        recent_lines = [l for l in log.stdout.strip().split("\n") if l.strip()]
        total_lines = [l for l in total_log.stdout.strip().split("\n") if l.strip()]

        if not total_lines:
            return None

        authors = set()
        has_security = False
        for line in recent_lines:
            parts = line.split("|", 2)
            if len(parts) >= 3:
                authors.add(parts[1])
                msg = parts[2].lower()
                if any(kw in msg for kw in self.SECURITY_KEYWORDS):
                    has_security = True

        recent = len(recent_lines)
        total = len(total_lines)
        author_count = len(authors)

        score = 0.0
        score += min(recent * 0.5, 10.0)
        score += min(author_count * 1.0, 5.0)
        if has_security:
            score += 5.0
        if total > 100:
            score += 2.0

        return FileRisk(
            file_path=file_path,
            commit_count=total,
            recent_commits=recent,
            authors=author_count,
            has_security_fixes=has_security,
            risk_score=round(score, 1),
        )
