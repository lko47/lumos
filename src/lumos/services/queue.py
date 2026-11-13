"""The scan queue: jobs recorded as a plan, not as evidence.

A queued job is an intention - targets, network and options - so it lives in a
JSON file beside the database (``<db>.queue.json``) rather than in a table: the
database holds measurements, and an intention that never ran is not a
measurement. Running the queue creates ordinary scan rows through the same
scope-checked path as a typed scan.

Any file on disk is hostile input. Every field is validated, re-sanitised and
capped on load, and a file that cannot be understood is an error with a
sentence, never a traceback or a silently empty queue.
"""

from __future__ import annotations

import json
import os
import uuid
from dataclasses import dataclass
from pathlib import Path

from ..core.scope import parse_target
from ..core.text import sanitize_text

MAX_QUEUE_JOBS = 32
MAX_JOB_TARGETS = 512
ENGINES = ("nmap", "masscan", "naabu", "rustscan")


class QueueError(ValueError):
    """A queue action that cannot be taken, with the reason in the sentence."""


@dataclass(frozen=True)
class Job:
    id: str
    network: str
    targets: tuple[str, ...]
    nmap_options: str = ""
    engine: str = "nmap"

    @property
    def summary(self) -> str:
        options = f" {self.nmap_options}" if self.nmap_options else ""
        return (
            f"{self.engine} {len(self.targets)} target(s)"
            f" -> {self.network}{options}"
        )


def queue_path(database: str | Path) -> Path:
    """``eng.sqlite`` -> ``eng.sqlite.queue.json``, beside the database."""
    source = Path(database)
    return source.with_name(source.name + ".queue.json")


def _clean_targets(targets: tuple[str, ...] | list[str]) -> tuple[str, ...]:
    cleaned: list[str] = []
    for raw in targets:
        target = sanitize_text(str(raw), max_chars=256).strip()
        if not target:
            continue
        try:
            parse_target(target)
        except ValueError as exc:
            raise QueueError(f"{target!r} is not a target: {exc}") from exc
        if target not in cleaned:
            cleaned.append(target)
    if not cleaned:
        raise QueueError("a queued job needs at least one target")
    if len(cleaned) > MAX_JOB_TARGETS:
        raise QueueError(f"a queued job holds at most {MAX_JOB_TARGETS} targets")
    return tuple(cleaned)


def load_jobs(database: str | Path) -> tuple[Job, ...]:
    """Read the queue, validating everything in it."""
    path = queue_path(database)
    if not path.exists():
        return ()
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise QueueError(f"cannot read the queue file: {exc}") from exc
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise QueueError(f"the queue file is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict) or payload.get("format") != "lumos-queue":
        raise QueueError("the queue file is not a Lumos queue")
    raw_jobs = payload.get("jobs")
    if not isinstance(raw_jobs, list):
        raise QueueError("the queue file has no job list")
    jobs: list[Job] = []
    for entry in raw_jobs[:MAX_QUEUE_JOBS]:
        if not isinstance(entry, dict):
            continue
        raw_targets = entry.get("targets")
        if not isinstance(raw_targets, list) or not all(
            isinstance(item, str) for item in raw_targets
        ):
            continue
        engine = entry.get("engine")
        engine = engine if engine in ENGINES else "nmap"
        network = sanitize_text(str(entry.get("network", "")), max_chars=120).strip()
        if not network:
            raise QueueError("a queued job has no network name")
        jobs.append(
            Job(
                id=sanitize_text(str(entry.get("id", "")), max_chars=64)
                or str(uuid.uuid4()),
                network=network,
                targets=_clean_targets(raw_targets),
                nmap_options=sanitize_text(
                    str(entry.get("nmap_options", "")), max_chars=500
                ).strip(),
                engine=engine,
            )
        )
    return tuple(jobs)


def _save(database: str | Path, jobs: tuple[Job, ...]) -> None:
    """Write through a temporary file so a crash cannot truncate the queue."""
    path = queue_path(database)
    payload = {
        "format": "lumos-queue",
        "version": 1,
        "jobs": [
            {
                "id": job.id,
                "network": job.network,
                "targets": list(job.targets),
                "nmap_options": job.nmap_options,
                "engine": job.engine,
            }
            for job in jobs
        ],
    }
    temporary = path.with_name(path.name + ".tmp")
    with open(temporary, "w", encoding="utf-8") as stream:
        json.dump(payload, stream, indent=2)
        stream.write("\n")
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)


def add_job(
    database: str | Path,
    *,
    network: str,
    targets: tuple[str, ...] | list[str],
    nmap_options: str = "",
    engine: str = "nmap",
) -> Job:
    """Append a job; identical jobs are refused rather than queued twice."""
    if engine not in ENGINES:
        raise QueueError(f"unknown engine {engine!r}")
    clean_network = sanitize_text(network, max_chars=120).strip()
    if not clean_network:
        raise QueueError("a queued job needs a network name")
    clean_options = sanitize_text(nmap_options, max_chars=500).strip()
    job = Job(
        id=str(uuid.uuid4()),
        network=clean_network,
        targets=_clean_targets(list(targets)),
        nmap_options=clean_options,
        engine=engine,
    )
    jobs = load_jobs(database)
    for existing in jobs:
        if (
            existing.network == job.network
            and existing.targets == job.targets
            and existing.nmap_options == job.nmap_options
            and existing.engine == job.engine
        ):
            raise QueueError(f"already queued as {existing.id[:8]}")
    if len(jobs) >= MAX_QUEUE_JOBS:
        raise QueueError(f"the queue holds at most {MAX_QUEUE_JOBS} jobs")
    _save(database, (*jobs, job))
    return job


def remove_job(database: str | Path, job_id: str) -> bool:
    """Drop one job by id or unique id prefix; False when nothing matched."""
    jobs = load_jobs(database)
    remaining = tuple(job for job in jobs if job.id != job_id)
    if len(remaining) == len(jobs):
        matches = [job for job in jobs if job.id.startswith(job_id)]
        if len(matches) != 1:
            return False
        target = matches[0]
        remaining = tuple(job for job in jobs if job.id != target.id)
    _save(database, remaining)
    return True


def clear(database: str | Path) -> int:
    """Empty the queue; returns how many jobs were dropped."""
    count = len(load_jobs(database))
    _save(database, ())
    return count


def next_job(database: str | Path) -> Job | None:
    """The job that would run next."""
    jobs = load_jobs(database)
    return jobs[0] if jobs else None