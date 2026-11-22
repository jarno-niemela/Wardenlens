#!/usr/bin/env bash
# Adversarial cases for spikes/s1-cameras (lib.sh and the probe scripts).
# Uses only fixtures under /tmp/claude-1000 and stub tools on PATH; never contacts a camera and never
# reads the real secret or inventory files. FAIL lines are findings.
# shellcheck disable=SC2016,SC2034,SC1091  # literal $ and backticks in fixtures; vars are read via check/eval
set -uo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
mkdir -p /tmp/claude-1000
fx=$(mktemp -d /tmp/claude-1000/s1-adv.XXXXXX)
trap 'rm -rf "$fx"' EXIT
fail=0
ok()   { echo "ok   $1"; }
bad()  { echo "FAIL $1"; fail=1; }
check() { if eval "$2"; then ok "$1"; else bad "$1"; fi; }

# Hostile but realistic passwords (JSON-escaped where needed).
PW1='p@ss:w/rd%41$HOME`id`'"'"'"x'
export HOME="$fx/home"; mkdir -p "$HOME"   # make sure the real ~/.config is never read
jq -n --arg p "$PW1" '[
  {name:"IPC-BO",      login:"admin", password:$p, onvif:"http://10.0.0.1:8000/onvif/device_service"},
  {name:"IPC-BO (2)",  login:"admin", password:$p},
  {name:"XR",          login:"admin", password:"q\"uo\\te"},
  {name:"C110",        login:"a&b<c", password:$p},
  {name:"HDIPC",       login:"admin"}
]' >"$fx/secret.json"
cat >"$fx/cameras.toml" <<'T'
[cameras.reolink-1]
host = "10.0.0.1"
[cameras.reolink-2]
host = "10.0.0.2"
[cameras.xr]
host = "127.0.0.1:PORT"
[cameras.tapo]
host = "10.0.0.4"
[cameras.hdipc]
host = "$(touch PWNED)10.0.0.5;touch PWNED2"
T
export WARDENLENS_SECRET_FILE="$fx/secret.json" WARDENLENS_CAMERAS="$fx/cameras.toml"

# Stub bin: ffprobe/ffmpeg record argv and echo the input URL on stderr (as real ffmpeg does in errors).
mkdir -p "$fx/bin"
for t in ffprobe ffmpeg; do
  cat >"$fx/bin/$t" <<S
#!/usr/bin/env bash
printf '%s\n' "\$*" >>"$fx/$t.argv"
for a in "\$@"; do case "\$a" in rtsp://*) echo "\$a: Server returned 401 Unauthorized" >&2;; esac; done
exit 1
S
  chmod +x "$fx/bin/$t"
done
export PATH="$fx/bin:$PATH"

# shellcheck source=../lib.sh
source "$here/lib.sh"

# --- lib.sh: rtsp_url round-trips hostile passwords ----------------------------
u=$(rtsp_url IPC-BO /x)
dec=$(python3 -I -c 'import sys,urllib.parse as p; print(p.unquote(p.urlsplit(sys.argv[1]).password))' "$u")
check "rtsp_url percent-encodes and round-trips password with @:/%\$\`'\"" '[[ "$dec" == "$PW1" ]]'
check "redact strips userinfo from rtsp_url output" '! grep -qF "$(uri_enc "$PW1")" <<<"$(echo "$u" | redact)"'

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

# --- missing keys / missing files ---------------------------------------------
cam_creds HDIPC
check "cam_creds: missing password yields empty, not literal 'null'" '[[ $CAM_PASS != null ]]'
check "cam_creds: unknown camera fails" '! (set -e; cam_creds NOPE; [[ -n $CAM_USER ]])'
check "cam_field: missing field is an error, not 'null'" '! cam_field HDIPC password >/dev/null 2>&1'
check "cam_creds: unknown camera is an error" '! cam_creds NOPE 2>/dev/null'
check "cam_host: missing inventory file fails" '! WARDENLENS_CAMERAS=/nonexistent bash -c "source \"$here/lib.sh\"; cam_host XR" 2>/dev/null'

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
sed -i "s/PORT/$port/" "$fx/cameras.toml"
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
dout=$("$here/dahua.sh" XR get / 2>&1); wait "$srv" 2>/dev/null
got=$(cat "$fx/auth" 2>/dev/null)
check "dahua.sh sends exact password containing \" and \\ (curl -K quoting)" '[[ $got == "admin:q\"uo\\te" ]]'
check "dahua.sh: password not on curl argv nor in output" '! grep -qF "uo\\te" "$fx/curl.argv" && [[ $dout != *uo* ]]'

# --- onvif.sh: XML escaping of username -------------------------------------------------------
printf '#!/usr/bin/env bash\nwhile (($#)); do [[ $1 == --data-binary ]] && { if [[ $2 == @- ]]; then cat >%q; else printf "%%s" "$2" >%q; fi; shift; }; shift; done\necho; echo "HTTP 000 0s"\n' \
  "$fx/env.xml" "$fx/env.xml.argv" >"$fx/bin/curl"
"$here/onvif.sh" C110 device '<tds:GetDeviceInformation/>' >/dev/null 2>&1
check "onvif.sh: envelope is well-formed XML when username contains & and <" \
  'python3 -I -c "import sys,xml.dom.minidom as m; m.parse(sys.argv[1])" "$fx/env.xml" 2>/dev/null'
check "onvif.sh: envelope is sent on stdin, not argv" '[[ -s $fx/env.xml ]]'
check "onvif.sh: hostile host never reaches shell (no PWNED)" '[[ ! -e $PWD/PWNED && ! -e $fx/PWNED ]]'

exit "$fail"
