#!/usr/bin/env bash
# Load the built module in a logoscore daemon and call it from the CLI.
#   nix build .#lgx-portable -o result-portable && tools/logoscore-smoke.sh            (LOGOSCORE_REV=0.3.1 KEEP_LOGS=1 …)
# The CLI reads as the host anchor, so this checks loading, dispatch and that the tier gate
# refuses the host: signer_info answers; caller_identity says "host"; signer_accounts, sign and
# derive_account are refused. A probe module calling as a named module is the next test.
set -uo pipefail
cd "$(dirname "$0")/.."
REV="${LOGOSCORE_REV:-0.3.1}"
LGX=$(ls result-portable/*.lgx 2>/dev/null | head -1)
[ -n "$LGX" ] || { echo "build first: nix build .#lgx-portable -o result-portable"; exit 1; }
# The portable CLI and lgpm, as Muster's scripts/split-platform-logoscore-test.sh takes them.
L="$(nix build "github:logos-co/logos-logoscore-cli/$REV#cli-bundle-dir" --no-link --print-out-paths --accept-flake-config 2>/dev/null | tail -1)/bin/logoscore"
LGPM="$(nix build github:logos-co/logos-package-manager/3133786ea86821e251fccc82a2eefbfc4db7605e#cli-portable --no-link --print-out-paths 2>/dev/null | tail -1)/bin/lgpm"
[ -x "$L" ] && [ -x "$LGPM" ] || { echo "logoscore or lgpm did not build"; exit 1; }

D=$(mktemp -d); mkdir -p "$D/mods" "$D/plugins" "$D/cfg"
"$LGPM" --modules-dir "$D/mods" --ui-plugins-dir "$D/plugins" --allow-unsigned install --file "$LGX" | tail -1
lc() { timeout 60 "$L" --config-dir "$D/cfg" "$@" 2>&1; }
setsid "$L" --config-dir "$D/cfg" daemon -m "$D/mods" --persistence-path "$D/cfg/data" >"$D/daemon.log" 2>&1 &
DPID=$!
cleanup() { lc stop >/dev/null; kill -9 -"$DPID" 2>/dev/null; kill -9 "$DPID" 2>/dev/null; }
trap cleanup EXIT
for _ in $(seq 1 20); do lc status >/dev/null && break; sleep 1; done

ok=1
result() { tail -1 | python3 -c 'import sys,json
try: print(json.load(sys.stdin)["result"])
except Exception: print("{}")'; }
echo "── load"; lc load-module context_signer_module | tail -1
info=$(lc call context_signer_module signer_info | result)
echo "signer_info: $info"
echo "$info" | python3 -c '
import sys,json; r=json.load(sys.stdin)
assert r["ok"] and r["interface"]=="logos.signer/1" and r["families"]==["ed25519"], r' || ok=0
who=$(lc call context_signer_module caller_identity | result)
echo "caller_identity: $who"
echo "$who" | python3 -c '
import sys,json; r=json.load(sys.stdin)
assert r["kind"]=="host" and r["managers"]==["signer_manager_module"] and r["custodians"]==[], r' || ok=0
for call in "signer_accounts" "sign {}" "derive_account {}" "unlock {}"; do
  out=$(lc call context_signer_module $call | result)
  echo "$call (as host): $out"
  echo "$out" | python3 -c 'import sys,json; assert json.load(sys.stdin)=={"ok":False,"error":"not authorized"}' || ok=0
done

if [ "$ok" = 1 ]; then echo "PASS: loads under logoscore $REV, answers, and refuses the host"; [ -n "${KEEP_LOGS:-}" ] && echo "logs: $D" || rm -rf "$D"; exit 0; fi
echo "FAIL — logs kept at $D"; tail -20 "$D/daemon.log"; exit 1
