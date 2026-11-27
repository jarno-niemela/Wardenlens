#!/usr/bin/env bash
# Adversarial cases for spikes/s1-cameras (lib.sh and the probe scripts).
# Uses only fixtures under a temporary directory and stub tools on PATH; never contacts a camera and never
# reads the real secret or inventory files. FAIL lines are findings.
# shellcheck disable=SC2016,SC2034,SC1091  # literal $ and backticks in fixtures; vars are read via check/eval
set -uo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
# Hermetic: nothing from the caller reaches the real vault, binary or a camera.
unset WARDENLENS_BIN WARDENLENS_VAULT WARDENLENS_VAULT_KEY_FILE WARDENLENS_VAULT_KEY CAMERAS
while read -r v; do unset "$v"; done < <(compgen -e | grep "^ONVIF_" || true)
fx=$(mktemp -d "${TMPDIR:-/tmp}/s1-adv.XXXXXX") || exit 1
trap 'rm -rf "$fx"' EXIT
fail=0
ok()   { echo "ok   $1"; }
bad()  { echo "FAIL $1"; fail=1; }
check() { if eval "$2"; then ok "$1"; else bad "$1"; fi; }

# Hostile but realistic passwords.
PW1='p@ss:w/rd%41$HOME`id`'"'"'"x'
export HOME="$fx/home"; mkdir -p "$HOME"   # the real ~/.config and ~/.local/share are never read
# shellcheck source=vault_stub.sh
source "$here/tests/vault_stub.sh"
cred reolink-1 admin "$PW1"
cred reolink-2 admin "$PW1"
cred xr admin 'q"uo\te'
cred tapo 'a&b<c' "$PW1"
vault_put cam:hdipc:credential.username admin
host reolink-1 10.0.0.1
host reolink-2 10.0.0.2
host xr 127.0.0.1:PORT
host tapo 10.0.0.4
host hdipc '$(touch PWNED)10.0.0.5;touch PWNED2'
# A credential with an empty password is a valid entry.
printf '' >"$VAULT_STUB/cam_hdipc_credential.password"

# Stub bin: ffprobe/ffmpeg record argv and echo the input URL on stderr (as real ffmpeg does in errors).
for t in ffprobe ffmpeg; do
  cat >"$fx/bin/$t" <<S
#!/usr/bin/env bash
printf '%s\n' "\$*" >>"$fx/$t.argv"
for a in "\$@"; do case "\$a" in rtsp://*) echo "\$a: Server returned 401 Unauthorized" >&2;; esac; done
exit 1
S
  chmod +x "$fx/bin/$t"
done

# shellcheck source=../lib.sh
source "$here/lib.sh"

redact_add "$(uri_enc "$PW1")"

# --- lib.sh: rtsp_url round-trips hostile passwords ----------------------------
u=$(rtsp_url reolink-1 /x)
dec=$(python3 -I -c 'import sys,urllib.parse as p; print(p.unquote(p.urlsplit(sys.argv[1]).password))' "$u")
check "rtsp_url percent-encodes and round-trips password with @:/%\$\`'\"" '[[ "$dec" == "$PW1" ]]'
check "redact removes the password from rtsp_url output (raw and encoded)" \
  'r=$(echo "$u" | redact); [[ $r != *"$(uri_enc "$PW1")"* && $r != *"$PW1"* ]]'

# --- redact edge cases -------------------------------------------------------
r=$(echo 'RTSP://admin:secret@10.0.0.1:554/x' | redact)
check "redact strips userinfo case-insensitively (RTSP://)" '[[ $r != *secret* ]]'
r=$(echo 'rtsp://admin:se/cret@cam.lan:554/x' | redact)
check "redact strips decoded userinfo containing '/'" '[[ $r != *cret* ]]'
r=$(echo 'rtsps://admin:secret@cam.lan/x https://u:secret@h/' | redact)
check "redact strips userinfo for rtsps/https" '[[ $r != *secret* ]]'

r=$(echo 'x aa:bb:cc:dd:ee:ff y fe80::1ff:fe23:4567:890a z <tds:SerialNumber>ABC123</tds:SerialNumber> "serialNumber":"XYZ789" at 12:30:01' | redact)
check "redact masks MAC, IPv6 and serial values but keeps clock times" \
  '[[ $r != *aa:bb* && $r != *fe80* && $r != *ABC123* && $r != *XYZ789* && $r == *12:30:01* ]]'
r=$(echo 'rtsps://admin:secret@cam.lan/x' | redact)
check "redact keeps the rtsps scheme" '[[ $r == rtsps://***@* ]]'

# --- redact: wiring, fail closed ---------------------------------------------
r=$(printf 'hello %s world\n' "$PW1" | redact)
check "redact replaces a vault value with the marker" '[[ $r == "hello [REDACTED] world" ]]'
for txt in 'frame=  250 fps= 25 q=-1.0 size=N/A time=00:00:10.00 bitrate=N/A speed=1.0x' \
  '[rtsp @ 0x55d4c3a0b2c0] method DESCRIBE failed: 401 Unauthorized' 'at 12:30:01.500 decode_slice_header error'; do
  r=$(printf '%s\n' "$txt" | redact); check "redact leaves ordinary text intact: $txt" '[[ $r == "$txt" ]]'
done
touch "$VAULT_STUB/.broken"
r=$(printf 'secret %s\n' "$PW1" | redact 2>/dev/null); rc=$?
check "redact fails closed with an unusable vault: no output, non-zero" '[[ -z $r && $rc != 0 ]]'
rm -f "$VAULT_STUB/.broken"
r=$(printf 'secret %s\n' "$PW1" | WARDENLENS_BIN=/nonexistent/wardenlens redact 2>/dev/null); rc=$?
check "redact fails closed with a missing binary: no output, non-zero" '[[ -z $r && $rc != 0 ]]'
r=$(printf 'secret %s\n' "$PW1" | PATH=/usr/bin:/bin WARDENLENS_BIN='' redact 2>/dev/null); rc=$?
check "redact fails closed when wardenlens is not on PATH: no output, non-zero" '[[ -z $r && $rc != 0 ]]'

# --- secrets never on argv of the vault binary -----------------------------------
: >"$VAULT_STUB/.argv"; cam_creds reolink-1; cam_host reolink-1 >/dev/null; echo "$u" | redact >/dev/null
check "wardenlens argv holds entry ids only, never a value" \
  '! grep -qF -e "$PW1" -e admin -e 10.0.0.1 "$VAULT_STUB/.argv" && grep -qx "vault get cam:reolink-1:credential --field password" "$VAULT_STUB/.argv"'
check "cam_creds returns the exact password" '[[ $CAM_PASS == "$PW1" && $CAM_USER == admin ]]'

# --- the legacy files and WARDENLENS_CAMERAS are not read by lib.sh ------------------
printf '[{"name":"xr","login":"legacyuser","password":"legacypass"}]' >"$fx/legacy.json"
printf '[cameras.xr]\nhost = "203.0.113.9"\n' >"$fx/legacy.toml"
check "lib.sh ignores WARDENLENS_SECRET_FILE / WARDENLENS_CAMERAS (legacy files)" \
  '(export WARDENLENS_SECRET_FILE="$fx/legacy.json" WARDENLENS_CAMERAS="$fx/legacy.toml"; cam_creds xr; [[ $CAM_USER == admin && $(cam_host xr) == 127.0.0.1:PORT ]])'
check "lib.sh source has no reference to the legacy files" '! grep -nE "secret\.json|cameras\.local|SECRET_FILE|WARDENLENS_CAMERAS" "$here/lib.sh" | grep -v "^[0-9]*:#"'

# --- missing entries -----------------------------------------------------------
check "cam_creds: missing password entry is an error, not an empty password" \
  '! (rm "$VAULT_STUB/cam_xr_credential.password"; cam_creds xr) 2>/dev/null'
cred xr admin 'q"uo\te'
check "cam_creds: empty password entry is allowed" '(cam_creds hdipc; [[ -z $CAM_PASS && $CAM_USER == admin ]])'
check "cam_creds: unknown camera is an error" '! cam_creds NOPE 2>/dev/null'
check "cam_creds: invalid camera name is an error" '! cam_creds "../x:y" 2>/dev/null'
check "cam_host: no host entry is an error" '! cam_host NOPE 2>/dev/null'
check "cam_creds: unusable vault is an error, variables empty" '! (touch "$VAULT_STUB/.broken"; cam_creds xr; true) 2>/dev/null; (touch "$VAULT_STUB/.broken"; cam_creds xr 2>/dev/null; rc=$?; rm "$VAULT_STUB/.broken"; [[ $rc != 0 && -z $CAM_USER && -z $CAM_PASS ]])'
check "cam_creds: a failure inside \$(...) aborts a set -e caller" \
  'o=$(bash -c '"'"'set -euo pipefail; source "$1/lib.sh"; url="$(rtsp_url NOPE /x)"; echo "URL=$url"'"'"' _ "$here" 2>/dev/null); [[ $? != 0 && $o != *URL=* ]]'

# --- probe_streams.sh: output and argv ------------------------------------------
out=$(cd "$fx" && "$here/probe_streams.sh" 2>&1)
check "probe_streams.sh output has no password (raw or encoded)" \
  '! grep -qF -e "$(uri_enc "$PW1")" -e "$PW1" <<<"$out"'
check "probe_streams.sh: hostile inventory host is not shell-evaluated" '[[ ! -e $fx/PWNED && ! -e $fx/PWNED2 ]]'
# ffprobe/ffmpeg take RTSP credentials only in the URL (argv): accepted spike-only risk, see ADR 0002.

# --- stream_soak.sh: log files -----------------------------------------------------
(cd "$fx" && "$here/stream_soak.sh" "$fx/soak" 3 >/dev/null 2>&1)
check "stream_soak.sh logs/summary contain no password" \
  '! grep -rqF -e "$(uri_enc "$PW1")" -e "$PW1" "$fx/soak"'
check "stream_soak.sh refuses a non-empty output directory" '! "$here/stream_soak.sh" "$fx/soak" 3 >/dev/null 2>&1'

# --- dahua.sh: curl config quoting -----------------------------------------------------
# A local server records the Basic auth it receives; a curl wrapper swaps --digest for --basic so the
# exact user:password curl parsed from the -K config becomes observable.
port=$(python3 -I -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1])')
host xr "127.0.0.1:$port"
python3 -I -c '
import socket,base64,sys
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind(("127.0.0.1",int(sys.argv[1]))); s.listen(1); s.settimeout(10)
c,_=s.accept(); d=c.recv(65536).decode("latin1")
for l in d.split("\r\n"):
  if l.lower().startswith("authorization: basic "): open(sys.argv[2],"wb").write(base64.b64decode(l.split()[2]))
c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"); c.close()' "$port" "$fx/auth" &
srv=$!
real_curl=$(command -v curl)
printf '#!/usr/bin/env bash\na=(); for x in "$@"; do [[ $x == --digest ]] && x=--basic; a+=("$x"); done\nprintf "%%s\\n" "$*" >>%q\nexec %q "${a[@]}"\n' \
  "$fx/curl.argv" "$real_curl" >"$fx/bin/curl"; chmod +x "$fx/bin/curl"
sleep 0.3
dout=$("$here/dahua.sh" xr get / 2>&1); wait "$srv" 2>/dev/null
got=$(cat "$fx/auth" 2>/dev/null)
check "dahua.sh sends exact password containing \" and \\ (curl -K quoting)" '[[ $got == "admin:q\"uo\\te" ]]'
check "dahua.sh: password not on curl argv nor in output" '! grep -qF "uo\\te" "$fx/curl.argv" && [[ $dout != *uo* ]]'

# --- onvif.sh: XML escaping of username -------------------------------------------------------
printf '#!/usr/bin/env bash\nwhile (($#)); do [[ $1 == --data-binary ]] && { if [[ $2 == @- ]]; then cat >%q; else printf "%%s" "$2" >%q; fi; shift; }; shift; done\necho; echo "HTTP 000 0s"\n' \
  "$fx/env.xml" "$fx/env.xml.argv" >"$fx/bin/curl"
"$here/onvif.sh" tapo device '<tds:GetDeviceInformation/>' >/dev/null 2>&1
check "onvif.sh: envelope is well-formed XML when username contains & and <" \
  'python3 -I -c "import sys,xml.dom.minidom as m; m.parse(sys.argv[1])" "$fx/env.xml" 2>/dev/null'
check "onvif.sh: envelope is sent on stdin, not argv" '[[ -s $fx/env.xml ]]'
check "onvif.sh: hostile host never reaches shell (no PWNED)" '[[ ! -e $PWD/PWNED && ! -e $fx/PWNED ]]'

exit "$fail"
