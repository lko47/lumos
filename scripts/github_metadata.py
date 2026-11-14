"""Apply repository metadata that cannot be committed: description, topics, release.

Requires a token with `Contents: read and write` (fine-grained) or `repo`:

    GH_TOKEN=... python3 scripts/github_metadata.py lko47/lumos
    GH_TOKEN=... python3 scripts/github_metadata.py lko47/lumos --dry-run

Every field is idempotent, so running it twice changes nothing the second time.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request

API = "https://api.github.com"
DESCRIPTION = "Terminal network mapper: Nmap evidence, a mouse-first topology, and exports that say what was measured"
TOPICS = ["network", "nmap", "security", "tui", "terminal", "topology", "python", "sqlite"]
RELEASE_NAME = "0.2.0 — evidence, topology and a safe way to share"


def _request(method: str, path: str, token: str, payload: dict | None = None) -> tuple[int, dict]:
    data = json.dumps(payload).encode() if payload is not None else None
    request = urllib.request.Request(
        f"{API}{path}", data=data, method=method,
        headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
                 "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request) as response:
            body = response.read().decode()
            return response.status, (json.loads(body) if body else {})
    except urllib.error.HTTPError as error:
        return error.code, {"message": error.read().decode()[:300]}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("repository", help="OWNER/REPO")
    parser.add_argument("--tag", default="v0.2.0")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    token = os.environ.get("GH_TOKEN", "").strip()
    if not token and not args.dry_run:
        print("lumos: GH_TOKEN is not set", file=sys.stderr)
        return 2
    plan = [
        ("PATCH", f"/repos/{args.repository}", {"description": DESCRIPTION}),
        ("PUT", f"/repos/{args.repository}/topics", {"names": TOPICS}),
        ("POST", f"/repos/{args.repository}/releases",
         {"tag_name": args.tag, "name": RELEASE_NAME, "draft": False, "prerelease": False,
          "body": "First tagged release: scope-checked scanning, a mouse-first topology map, "
                  "pseudonymised sharing, plugins, and exports that distinguish evidence from inference."}),
    ]
    for method, path, payload in plan:
        if args.dry_run:
            print(f"{method} {path} {json.dumps(payload)[:90]}")
            continue
        status, body = _request(method, path, token, payload)
        state = "ok" if status < 300 else f"HTTP {status}"
        print(f"{method} {path}: {state}")
        if status >= 300 and path.endswith("/releases"):
            print(f"  (a release for {args.tag} may already exist: {body.get('errors') or body.get('message')})")
        elif status >= 300:
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
