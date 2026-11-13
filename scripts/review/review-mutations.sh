#!/bin/bash
# Mutation checks: each mutation is applied in isolation, the full suite is run,
# and the result is recorded. The worktree is restored between mutations.
set -u
cd ${TMPDIR:-/tmp}/lumos-review || exit 1
run_suite() { PYTHONPATH=src python3.11 -m unittest discover -s tests 2>&1; }

mutation() {
  local name="$1"; shift
  echo "=== $name ==="
  "$@"
  local out
  out=$(run_suite)
  if echo "$out" | tail -3 | grep -q '^OK'; then
    echo "RESULT: SURVIVED (suite still passes)"
  else
    echo "RESULT: caught"
    echo "$out" | grep -E '^(FAIL|ERROR):' | head -5
    echo "$out" | tail -3
  fi
  git checkout -- src tests
}

m1() { python3 - <<'EOF'
import pathlib
p = pathlib.Path("src/lumos/core/inference.py")
s = p.read_text()
s2 = s.replace("    ON_LINK_ARP: 0.95,", "    ON_LINK_ARP: 0.55,")
assert s2 != s
p.write_text(s2)
EOF
}

m2() { python3 - <<'EOF'
import pathlib
p = pathlib.Path("src/lumos/core/inference.py")
s = p.read_text()
old = "        if (vantage_id, host.node_id) in observed:\n            continue\n"
assert old in s
p.write_text(s.replace(old, "        if False and (vantage_id, host.node_id) in observed:\n            continue\n"))
EOF
}

m3() { python3 - <<'EOF'
import pathlib
p = pathlib.Path("src/lumos/core/inference.py")
s = p.read_text()
old = "                and host.mac.lower() not in suspicious\n"
assert old in s
p.write_text(s.replace(old, "                and True\n"))
EOF
}

m4() { python3 - <<'EOF'
import pathlib
p = pathlib.Path("src/lumos/core/scanning.py")
s = p.read_text()
old = """def _check_target_scope(targets: Sequence[str], rules: list[ScopeRule]) -> list[str]:
    outside: list[str] = []"""
assert old in s
p.write_text(s.replace(old, """def _check_target_scope(targets: Sequence[str], rules: list[ScopeRule]) -> list[str]:
    return []
    outside: list[str] = []"""))
EOF
}

m5() { python3 - <<'EOF'
import pathlib
p = pathlib.Path("src/lumos/core/text.py")
s = p.read_text()
old = '    text = _ANSI_ESCAPE.sub("", text)\n'
assert old in s
p.write_text(s.replace(old, ""))
EOF
}

mutation "M1 confidence ON_LINK_ARP 0.95 -> 0.55" m1
mutation "M2 observed traceroute no longer overrides inferred" m2
mutation "M3 proxy-ARP downgrade removed" m3
mutation "M4 scope check before scan skipped" m4
mutation "M5 ANSI escape stripping removed (one display path)" m5
echo "worktree status:"; git status --short
