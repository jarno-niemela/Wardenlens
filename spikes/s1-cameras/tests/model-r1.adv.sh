#!/usr/bin/env bash
# Adversarial cases for #233: rtsp_path by catalogue model, and load_cams duplicate detection after the id rename.
# Stub vault under a temporary HOME; never the real vault or a camera. FAIL lines are findings.
# shellcheck disable=SC2016,SC2034,SC1091  # literal $ in check expressions; sourced files are checked separately
set -uo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
repo=$(cd "$here/../.." && pwd)
unset WARDENLENS_BIN WARDENLENS_VAULT WARDENLENS_VAULT_KEY_FILE WARDENLENS_VAULT_KEY CAMERAS XDG_CONFIG_HOME XDG_DATA_HOME BASH_ENV ENV
fx=$(mktemp -d "${TMPDIR:-/tmp}/s1-model.XXXXXX") || exit 1
trap 'rm -rf "$fx"' EXIT
fail=0
ok()   { echo "ok   $1"; }
bad()  { echo "FAIL $1"; fail=1; }
check() { if eval "$2"; then ok "$1"; else bad "$1"; fi; }
export HOME="$fx/home"; mkdir -p "$HOME"
# shellcheck source=vault_stub.sh
source "$here/tests/vault_stub.sh"
# shellcheck source=../lib.sh
source "$here/lib.sh"

# Oracle: every catalogue model's rtsp paths[0] (main) and paths[1] (sub) from cameras/<vendor>/<model>.toml.
n=0
while IFS=$'\t' read -r slug main sub; do
  n=$((n + 1))
  host c-$n 192.0.2.$n; model c-$n "$slug"
  check "rtsp_path main for $slug is the catalogue's first path" '[[ $(rtsp_path c-$n main) == "$main" ]]'
  check "rtsp_path sub for $slug is the catalogue's second path" '[[ $(rtsp_path c-$n sub) == "$sub" ]]'
done < <(python3 -I - "$repo/cameras" <<'PY'
import sys, pathlib, tomllib
for p in sorted(pathlib.Path(sys.argv[1]).glob("*/*.toml")):
    d = tomllib.loads(p.read_text())
    def find(o):
        if isinstance(o, dict):
            if "paths" in o and isinstance(o["paths"], list):
                return o["paths"]
            for v in o.values():
                r = find(v)
                if r: return r
        if isinstance(o, list):
            for v in o:
                r = find(v)
                if r: return r
    paths = find(d)
    print(f"{p.parent.name}/{p.stem}\t{paths[0]}\t{paths[1]}")
PY
)
check "the oracle saw every catalogue model" '(( n == $(find "$repo/cameras" -mindepth 2 -name "*.toml" | wc -l) && n > 0 ))'

# Errors are clear and name the vault entry; nothing is printed on stdout.
host c-none 192.0.2.50
err=$(rtsp_path c-none main 2>&1 >/dev/null); out=$(rtsp_path c-none main 2>/dev/null); rc=$?
check "a camera with no model entry: error naming cam:<id>:model, empty stdout" \
  '(( rc != 0 )) && [[ -z $out && $err == *"cam:c-none:model"* ]]'
host c-unk 192.0.2.51; model c-unk acme/x-1
err=$(rtsp_path c-unk main 2>&1 >/dev/null); out=$(rtsp_path c-unk main 2>/dev/null); rc=$?
check "an unknown model: error naming the model, empty stdout" '(( rc != 0 )) && [[ -z $out && $err == *acme/x-1* ]]'
for m in 'Reolink/RLC-520A' 'reolink/rlc-520a/x' 'reolink' '/rlc-520a' 'reolink/' $'reolink/rlc-520a\r' ' reolink/rlc-520a' 'reolink/rlc-520a;id'; do
  model c-bad "$m"; host c-bad 192.0.2.52
  out=$(rtsp_path c-bad main 2>/dev/null); rc=$?
  check "a malformed model entry <${m//$'\r'/\\r}> is refused with empty stdout" '(( rc != 0 )) && [[ -z $out ]]'
done

# load_cams: a duplicate across a newline/tab is refused *as a duplicate* (both entries otherwise usable).
no_entries
host cam-6 192.0.2.2; model cam-6 dahua/ipc-hfw4431r-z
err=$(CAMERAS=$'cam-6\n\tcam-6' load_cams 2>&1); rc=$?
check "load_cams: cam-6 newline/tab cam-6 is refused because it is a duplicate" '(( rc != 0 )) && [[ $err == *"duplicate camera id"* ]]'
check "load_cams: a usable single camera is accepted (control)" '{ CAMERAS=cam-6 load_cams && [[ ${CAMS[*]} == cam-6 ]]; }'
# A camera without a model entry is refused by load_cams (it would otherwise open a bare host).
host cam-7 192.0.2.7
check "load_cams: a camera without a model entry is refused" '! CAMERAS="cam-6 cam-7" load_cams 2>/dev/null && (( ${#CAMS[@]} == 0 ))'

exit $fail
