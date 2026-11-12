"""Synthetic scale benchmark for the Lumos map read/render path.

This is a development tool, not part of the runtime package. It writes a
throwaway engagement database with N synthetic hosts using the same
deterministic ids as the application, then measures:

* how long it takes to build the fixture (bulk SQL, not the Nmap writer),
* the database file size,
* ``load_map_snapshot`` with the TUI default bound and unbounded,
* one full TUI frame per screen at 110x32.

Traced hosts get a traceroute link from the scanner root; the rest get the
marked ``inferred`` link, so both edge styles are exercised.

Usage:
    PYTHONPATH=src python3 bench/map_benchmark.py --hosts 10000 100000
"""

from __future__ import annotations

import argparse
import os
import statistics
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from lumos.core import ids  # noqa: E402
from lumos.core.database import initialize_database, open_database, utc_now  # noqa: E402
from lumos.services.map_view import load_map_snapshot  # noqa: E402
from lumos.tui import render, theme  # noqa: E402

TRACED_FRACTION = 0.2
BATCH = 5000
WIDTH, HEIGHT = 110, 32


class RecordingWindow:
    """Minimal curses window that accepts text and discards it."""

    def __init__(self, height: int = HEIGHT, width: int = WIDTH) -> None:
        self.height = height
        self.width = width

    def getmaxyx(self) -> tuple[int, int]:
        return self.height, self.width

    def erase(self) -> None:
        pass

    def addnstr(self, *_args, **_kwargs) -> None:
        pass

    def addch(self, *_args, **_kwargs) -> None:
        pass

    def refresh(self) -> None:
        pass


def build_database(path: Path, hosts: int) -> tuple[str, float]:
    started = time.perf_counter()
    engagement_id = initialize_database(path, f"benchmark {hosts} hosts")
    conn = open_database(path)
    try:
        uid = ids.ensure_engagement_uid(conn)
        now = utc_now()
        scan_id = ids.trace_path_id(uid, "benchmark", 0)  # any stable uuid for the fixture
        vantage_id = ids.vantage_id(uid, "bench-scanner")
        root_id = ids.node_id(uid, "root", vantage_id)
        network_id = ids.network_id(uid, "lab")
        traced_edges: list[tuple] = []
        inferred_edges: list[tuple] = []
        with conn:
            conn.execute(
                "INSERT INTO networks(id, engagement_id, name, cidr, family, notes, created_at) "
                "VALUES (?, ?, 'lab', '10.0.0.0/8', 4, '', ?)",
                (network_id, engagement_id, now),
            )
            conn.execute(
                "INSERT INTO vantage_points(id, engagement_id, scanner_name, operator, created_at) "
                "VALUES (?, ?, 'bench-scanner', 'bench', ?)",
                (vantage_id, engagement_id, now),
            )
            conn.execute(
                "INSERT INTO topology_nodes(id, engagement_id, kind, entity_id, label, created_at) "
                "VALUES (?, ?, 'root', ?, 'bench-scanner', ?)",
                (root_id, engagement_id, vantage_id, now),
            )
            conn.execute(
                "INSERT INTO scans(id, engagement_id, vantage_point_id, exact_args_json, redacted_args_json, "
                "targets_json, nmap_version, interface, operator, started_at, ended_at, exit_code, status) "
                "VALUES (?, ?, ?, '[]', '[]', ?, '7.99', '', 'bench', ?, ?, 0, 'completed')",
                (scan_id, engagement_id, vantage_id, '{"requested": ["10.0.0.0/8"], "resolved": []}', now, now),
            )
            for start in range(0, hosts, BATCH):
                stop = min(hosts, start + BATCH)
                devices, observations, addresses, obs_addresses, ports, nodes = [], [], [], [], [], []
                for index in range(start, stop):
                    octet = index % 65536
                    address_text = f"10.{(index // 65536) % 256}.{octet // 256}.{octet % 256}"
                    device_id = ids.device_id(uid, scan_id, index)
                    observation_id = ids.observation_id(device_id)
                    address_id = ids.address_id(network_id, "ipv4", address_text)
                    node_id = ids.node_id(uid, "device", device_id)
                    devices.append((device_id, engagement_id, now))
                    observations.append(
                        (
                            observation_id,
                            scan_id,
                            device_id,
                            now,
                            "up",
                            "syn-ack",
                            f"host-{index}.bench.invalid",
                            "Linux 6.x",
                            95,
                            "",
                            0.001,
                            "{}",
                        )
                    )
                    addresses.append((address_id, network_id, "ipv4", address_text, address_text, now))
                    obs_addresses.append((observation_id, address_id, "ipv4"))
                    ports.append((ids.port_observation_id(observation_id, "tcp", 22), observation_id,
                                  "tcp", 22, "open", "ssh", "OpenSSH", "9.9", "", ""))
                    ports.append((ids.port_observation_id(observation_id, "tcp", 443), observation_id,
                                  "tcp", 443, "open", "https", "nginx", "1.24", "", ""))
                    nodes.append((node_id, engagement_id, "device", device_id,
                                  f"host-{index}.bench.invalid", now))
                    if index < hosts * TRACED_FRACTION:
                        traced_edges.append(
                            (
                                ids.edge_id(uid, root_id, node_id, "traceroute", "nmap_xml"),
                                engagement_id,
                                root_id,
                                node_id,
                                "traceroute",
                                "nmap_xml",
                                scan_id,
                                1.0,
                                now,
                                now,
                            )
                        )
                    else:
                        inferred_edges.append(
                            (
                                ids.edge_id(uid, root_id, node_id, "inferred", "inference"),
                                engagement_id,
                                root_id,
                                node_id,
                                "inferred",
                                "inference",
                                scan_id,
                                0.35,
                                now,
                                None,
                            )
                        )
                conn.executemany(
                    "INSERT INTO devices(id, engagement_id, created_at) VALUES (?, ?, ?)", devices
                )
                conn.executemany(
                    "INSERT INTO host_observations(id, scan_id, device_id, observed_at, reachability, "
                    "discovery_method, hostname, os_name, os_accuracy, mac_vendor, latency_seconds, raw_host_json) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    observations,
                )
                conn.executemany(
                    "INSERT INTO addresses(id, network_id, kind, normalized_value, display_value, created_at) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    addresses,
                )
                conn.executemany(
                    "INSERT INTO observation_addresses(host_observation_id, address_id, role) VALUES (?, ?, ?)",
                    obs_addresses,
                )
                conn.executemany(
                    "INSERT INTO port_observations(id, host_observation_id, protocol, port, state, service, "
                    "product, version, tunnel, extra_info) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    ports,
                )
                conn.executemany(
                    "INSERT INTO topology_nodes(id, engagement_id, kind, entity_id, label, created_at) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    nodes,
                )
            conn.executemany(
                "INSERT INTO topology_edges(id, engagement_id, from_node_id, to_node_id, edge_type, "
                "source_kind, source_id, confidence, first_observed_at, last_confirmed_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                traced_edges + inferred_edges,
            )
        return engagement_id, time.perf_counter() - started
    finally:
        conn.close()


def timed(function, repeat: int) -> tuple[float, float]:
    samples = []
    for _ in range(repeat):
        started = time.perf_counter()
        function()
        samples.append(time.perf_counter() - started)
    return statistics.median(samples), max(samples)


def measure(hosts: int) -> dict[str, object]:
    tmp = tempfile.TemporaryDirectory()
    try:
        path = Path(tmp.name) / f"bench-{hosts}.sqlite"
        _engagement, build_seconds = build_database(path, hosts)
        size_mb = path.stat().st_size / (1024 * 1024)
        bounded = load_map_snapshot(path)
        build_load, _ = timed(lambda: load_map_snapshot(path), 5)
        full_started = time.perf_counter()
        full = load_map_snapshot(path, max_nodes=hosts + 10)
        load_full_seconds = time.perf_counter() - full_started
        styles = theme.init_styles("aurora", theme.CAPABILITY_256)

        def frame() -> None:
            window = RecordingWindow()
            state = render.ViewState()
            render.draw_header(window, bounded, state, styles, True, "aurora", "256")
            render.draw_map_screen(window, bounded, state, styles, True)
            render.draw_footer(window, bounded, state, styles, True, 0.0)

        frame_seconds, _ = timed(frame, 5)
        return {
            "hosts": hosts,
            "build_s": build_seconds,
            "size_mb": size_mb,
            "nodes_total": len(full.nodes),
            "not_shown_default": bounded.not_shown,
            "load_default_ms": build_load * 1000,
            "load_full_ms": load_full_seconds * 1000,
            "full_nodes": len(full.nodes),
            "frame_ms": frame_seconds * 1000,
            "edges": len(full.edges),
        }
    finally:
        tmp.cleanup()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hosts", type=int, nargs="+", default=[10_000, 100_000])
    args = parser.parse_args()
    print(f"python {sys.version.split()[0]}  cpus {os.cpu_count()}  platform {sys.platform}")
    for hosts in args.hosts:
        started = time.perf_counter()
        result = measure(hosts)
        print(
            f"hosts={hosts:>7}  build={result['build_s']:.1f}s  size={result['size_mb']:.1f}MB  "
            f"nodes={result['nodes_total']}  edges={result['edges']}"
        )
        print(
            f"           load(default 2000)={result['load_default_ms']:.1f}ms  "
            f"not_shown={result['not_shown_default']}  "
            f"load(all {result['full_nodes']})={result['load_full_ms']:.0f}ms  "
            f"frame={result['frame_ms']:.1f}ms"
        )
        print(f"           total wall {time.perf_counter() - started:.1f}s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
