#!/usr/bin/env bash
# Round-2 adversarial cases for spikes/s1-cameras: attacks on the round-1 fixes.
# Fake fixtures under /tmp/claude-1000 and stub tools on PATH only; never contacts a camera and never
# reads the real secret or inventory files. FAIL lines are findings.
# shellcheck disable=SC2016,SC2034,SC1091,SC1003  # literal $ in fixtures; vars are read via check/eval
set -uo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
mkdir -p /tmp/claude-1000
fx=$(mktemp -d /tmp/claude-1000/s1-adv2.XXXXXX)
trap 'chmod -R u+rwx "$fx" 2>/dev/null; rm -rf "$fx"' EXIT
fail=0
ok()   { echo "ok   $1"; }
bad()  { echo "FAIL $1"; fail=1; }
check() { if eval "$2"; then ok "$1"; else bad "$1"; fi; }

export HOME="$fx/home"; mkdir -p "$HOME"   # the real ~/.config is never read
# secret <json-array> : (re)write the fake secret file
secret() { printf '%s' "$1" >"$fx/secret.json"; }
secret '[{"name":"XR","login":"admin","password":"x"},{"name":"C110","login":"admin","password":"x"},
 {"name":"HDIPC","login":"admin","password":"x"}]'
cat >"$fx/cameras.toml" <<'T'
[cameras.reolink-1]
host = "10.0.0.1"
[cameras.reolink-2]
host = "10.0.0.2"
[cameras.xr]
host = "127.0.0.1:PORT"
[cameras.tapo]
host = "10.0.0.4"
onvif_port = 2020
[cameras.hdipc]
host = "10.0.0.5"
onvif_port = 8000
T
export WARDENLENS_SECRET_FILE="$fx/secret.json" WARDENLENS_CAMERAS="$fx/cameras.toml"
mkdir -p "$fx/bin"; export PATH="$fx/bin:$PATH"
# shellcheck source=../lib.sh
source "$here/lib.sh"

# ============================== redact ==============================
R() { printf '%s\n' "$1" | redact; }
r=$(R 'RTSPS://admin:s3cr3t@cam.lan/x'); check "redact: upper-case RTSPS masked, scheme kept" '[[ $r != *s3cr3t* && $r == RTSPS://***@* ]]'
r=$(R 'HtTpS://u:s3cr3t@h/'); check "redact: mixed-case HtTpS masked" '[[ $r != *s3cr3t* ]]'
r=$(R 'rtsp://admin:a/b@c@cam.lan:554/x tail'); check "redact: raw '/' and '@' in password masked up to last @" '[[ $r != *a/b* && $r != *c@* && $r == *cam.lan:554/x\ tail ]]'
r=$(R '"url":"rtsp://admin:s3cr3t@cam.lan/x"'); check "redact: quoted URL masked" '[[ $r != *s3cr3t* ]]'
r=$(R 'a AA-BB-CC-DD-EE-FF b 0a:1b:2c:3d:4e:5f c'); check "redact: MAC upper/dash and lower/colon" '[[ $r != *AA-BB* && $r != *0a:1b* && $r == "a <mac> b <mac> c" ]]'
for v6 in '2001:db8::1' '::1' 'FD00::ABCD:5' '2001:0db8:0000:0000:0000:ff00:0042:8329' '[2001:db8:85a3::8a2e:370:7334]:80' '::ffff:10.0.0.1'; do
  r=$(R "x $v6 y"); check "redact: IPv6 $v6 masked" '[[ $r != *db8* && $r != *abcd* && $r != *ABCD* && $r != *8329* && $r != *7334* && $r != *ffff* && $r != *::1* ]]'
done
r=$(R '<tt:HardwareId>HW-77</tt:HardwareId> <SerialNumber xmlns="urn:x">SN-11</SerialNumber> serialNumber: "SN-22" SERIALNUMBER=SN-33')
check "redact: HardwareId/SerialNumber (ns attr, Debug, upper-case) masked" '[[ $r != *HW-77* && $r != *SN-11* && $r != *SN-22* && $r != *SN-33* ]]'
r=$(R 'serial_number: "SN-44"'); check "redact: snake_case serial_number masked (Rust Debug output)" '[[ $r != *SN-44* ]]'
# No over-redaction of ordinary log text.
for txt in 'frame=  250 fps= 25 q=-1.0 size=N/A time=00:00:10.00 bitrate=N/A speed=1.0x' \
  '[rtsp @ 0x55d4c3a0b2c0] method DESCRIBE failed: 401 Unauthorized' \
  'see http://cam.lan/onvif/device_service and mail ops@example.org' \
  'at 12:30:01.500 decode_slice_header error' 'Error: io::Error kind: std::io::ErrorKind::Other' \
  'ffmpeg version 6.1.1 codec h264 profile Main' 'neolink_core::bc_protocol::errors'; do
  r=$(R "$txt"); check "redact: leaves ordinary text intact: $txt" '[[ $r == "$txt" ]]'
done

# ============================== cam_field / cam_creds / rtsp_url ==============================
secret '[{"name":"XR","login":null,"password":"p"},{"name":"C110","login":"","password":null},
 {"name":"HDIPC","login":"a","password":"p1"},{"name":"HDIPC","login":"b","password":"p2"}]'
check "cam_creds: explicit null login is an error" '! cam_creds XR 2>/dev/null'
cam_creds C110 2>/dev/null; rc=$?
check "cam_creds: empty login + null password -> ok, empty strings" '[[ $rc == 0 && -z $CAM_USER && -z $CAM_PASS ]]'
cam_creds HDIPC 2>/dev/null; rc=$?
check "cam_creds: duplicate camera entries are an error, not a multi-line user" '[[ $rc != 0 || $CAM_USER != *$'"'"'\n'"'"'* ]]'
check "cam_creds: missing secret file is an error" '! (SECRET_FILE=/nonexistent; cam_creds C110) 2>/dev/null'
secret '[{"name":"C110","login":"admin","password":"p"}]'
# Callers use url="$(rtsp_url ...)" under set -e; errexit is not inherited by command substitution.
o=$(bash -c 'set -euo pipefail; source "$1/lib.sh"; url="$(rtsp_url XR /x)"; echo "URL=$url"' _ "$here" 2>/dev/null); rc=$?
check "rtsp_url in \$(...): camera missing from secret file aborts the caller (no credential-less URL)" '[[ $rc != 0 && $o != *URL=* ]]'
o=$(bash -c 'set -euo pipefail; source "$1/lib.sh"; url="$(rtsp_url NOPE /x)"; echo "URL=$url"' _ "$here" 2>/dev/null); rc=$?
check "rtsp_url in \$(...): unknown camera aborts the caller" '[[ $rc != 0 && $o != *URL=* ]]'

# ============================== dahua.sh ==============================
# Capture what curl parsed from -K: swap --digest for --basic and decode Basic auth at a local server.
real_curl=$(command -v curl)
printf '#!/usr/bin/env bash\na=(); for x in "$@"; do [[ $x == --digest ]] && x=--basic; a+=("$x"); done\necho called >>%q\nexec %q "${a[@]}"\n' \
  "$fx/curl.called" "$real_curl" >"$fx/bin/curl"; chmod +x "$fx/bin/curl"
port=$(python3 -I -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1])')
sed -i "s/PORT/$port/" "$fx/cameras.toml"
serve() {
  python3 -I -c '
import socket,base64,sys
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind(("127.0.0.1",int(sys.argv[1]))); s.listen(1); s.settimeout(5)
c,_=s.accept(); d=c.recv(65536).decode("latin1")
for l in d.split("\r\n"):
  if l.lower().startswith("authorization: basic "): open(sys.argv[2],"wb").write(base64.b64decode(l.split()[2]))
c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"); c.close()' "$port" "$fx/auth" &
  srv=$!; sleep 0.3
}
for pw in 'a\tb\nc' $'tab\there' ' lead and trail ' 'ends\' '#hash;semi' "q'uo\"te" 'ünï€' '\\\"'; do
  secret "$(jq -n --arg p "$pw" '[{name:"XR",login:"admin",password:$p}]')"
  rm -f "$fx/auth"; serve
  "$here/dahua.sh" XR get / >/dev/null 2>&1; wait "$srv" 2>/dev/null
  got=$(cat "$fx/auth" 2>/dev/null; echo .); got=${got%.}
  check "dahua.sh: password round-trips through curl -K: $(printf %q "$pw")" '[[ $got == "admin:$pw" ]]'
done
for pw in $'a\nb' $'a\rb' $'a\r\nuser = "evil:x"'; do
  secret "$(jq -n --arg p "$pw" '[{name:"XR",login:"admin",password:$p}]')"
  rm -f "$fx/curl.called"
  out=$("$here/dahua.sh" XR get / 2>&1); rc=$?
  check "dahua.sh: refuses CR/LF password $(printf %q "$pw") before curl, no echo" '[[ $rc != 0 && ! -e $fx/curl.called && $out != *evil* ]]'
done
secret "$(jq -n '[{name:"XR",login:"ad\nmin",password:"p"}]')"; rm -f "$fx/curl.called"
"$here/dahua.sh" XR get / >/dev/null 2>&1; rc=$?
check "dahua.sh: refuses CR/LF username" '[[ $rc != 0 && ! -e $fx/curl.called ]]'
secret "$(jq -n '[{name:"XR",login:"admin",password:"pw\n"}]')"; rm -f "$fx/curl.called"
"$here/dahua.sh" XR get / >/dev/null 2>&1; rc=$?
check "dahua.sh: password with trailing newline is refused, not silently truncated" '[[ $rc != 0 && ! -e $fx/curl.called ]]'

# ============================== onvif.sh ==============================
printf '#!/usr/bin/env bash\nprintf "%%s\\n" "$@" >%q\ncat >%q\necho; echo "HTTP 200 0s"\n' "$fx/onvif.argv" "$fx/env.xml" >"$fx/bin/curl"
UH=$'a&b<c>d"e\'f]]>&amp;'; PH='p&<>"'"'"'$(id)`x`\'
secret "$(jq -n --arg u "$UH" --arg p "$PH" '[{name:"C110",login:$u,password:$p}]')"
"$here/onvif.sh" C110 device '<tds:GetDeviceInformation/>' >/dev/null 2>&1
v=$(python3 -I - "$fx/env.xml" "$UH" "$PH" <<'PY' 2>&1
import sys,base64,hashlib,xml.dom.minidom as m
d=m.parse(sys.argv[1]); t=lambda n:d.getElementsByTagName(n)[0].firstChild.data
u=t("Username"); n=base64.b64decode(t("Nonce")); c=t("Created")
dg=base64.b64encode(hashlib.sha1(n+c.encode()+sys.argv[3].encode()).digest()).decode()
print("user" if u==sys.argv[2] else "baduser", "digest" if dg==t("Password") else "baddigest")
PY
)
check "onvif.sh: hostile username parses back exactly" '[[ $v == "user "* ]]'
check "onvif.sh: PasswordDigest correct for hostile password" '[[ $v == *" digest" ]]'
check "onvif.sh: no digest/nonce/envelope on curl argv" '! grep -qE "PasswordDigest|Envelope|Username" "$fx/onvif.argv" && grep -qx -- "@-" "$fx/onvif.argv"'

# ============================== onvif_pull.sh origin check ==============================
# Copy the scripts and replace onvif.sh with a stub: CreatePullPoint returns $PP_ADDR, a "full" call
# (following the address) is recorded and returns a hostile notification.
cp -r "$here" "$fx/s1"
cat >"$fx/s1/onvif.sh" <<'S'
#!/usr/bin/env bash
case "$2" in
  events) printf '<tev:SubscriptionReference><wsa5:Address>%s</wsa5:Address></tev:SubscriptionReference>\nHTTP 200 0s\n' "$PP_ADDR" ;;
  full) echo "$ONVIF_FULL_URL" >>"$PP_LOG"
        printf '<wsnt:Topic>tns1:Rule\x1b]0;pwn\x07\x1b[2J</wsnt:Topic><tt:SimpleItem Name="X" Value="aa:bb:cc:dd:ee:ff fd00::5"/>\nHTTP 200 0s\n' ;;
esac
S
chmod +x "$fx/s1/onvif.sh"
secret '[{"name":"HDIPC","login":"admin","password":"p"},{"name":"C110","login":"admin","password":"p"}]'
pull() { # <cam> <addr> -> 0 if the address was followed
  : >"$fx/pp.log"; PP_LOG="$fx/pp.log" PP_ADDR="$2" timeout 10 "$fx/s1/onvif_pull.sh" "$1" 1 >"$fx/pp.out" 2>&1
  [[ -s $fx/pp.log ]]
}
check "onvif_pull: same origin is followed" 'pull HDIPC http://10.0.0.5:8000/onvif/pp'
# Host-only comparison (Tapo serves the pull point on another port); fragment/query text is not authority.
for a in http://10.0.0.5:8001/x http://10.0.0.5/x http://10.0.0.5:80/x 'http://10.0.0.5:8000#@evil.example/'; do
  check "onvif_pull: same host, other port or fragment is followed: $a" 'pull HDIPC "$a"'
done
for a in 'http://10.0.0.5:8000@evil.example/x' 'http://10.0.0.5.:8000/x' 'http://10.0.0.50:8000/x' \
  'http://10.0.0.5:8000.evil.example/x' 'http://evil@10.0.0.5:8000/x' \
  'http://10.0.0.5:8000\@evil.example/x' 'http://[::ffff:10.0.0.5]:8000/x' \
  'http://10.0.0.5:8000/x>http://evil.example/y'; do
  check "onvif_pull: refuses $a" '! pull HDIPC "$a"'
done
pull HDIPC http://10.0.0.5:8000/onvif/pp
check "onvif_pull: control chars stripped from camera text" '! grep -q $'"'"'\x1b'"'"' "$fx/pp.out" && ! grep -q $'"'"'\x07'"'"' "$fx/pp.out"'
check "onvif_pull: MAC / IPv6 in event text are masked" '! grep -qE "aa:bb:cc|fd00::5" "$fx/pp.out"'
sed -i 's/^host = "10.0.0.5"/host = "[fd00::5]"/' "$fx/cameras.toml"
check "onvif_pull: IPv6 camera, same origin is followed" 'pull HDIPC "http://[fd00::5]:8000/onvif/pp"'
check "onvif_pull: IPv6 camera, other host refused" '! pull HDIPC "http://[fd00::6]:8000/onvif/pp"'

# ============================== stream_soak.sh ==============================
printf '#!/usr/bin/env bash\nexit 1\n' >"$fx/bin/ffmpeg"; chmod +x "$fx/bin/ffmpeg"
secret '[{"name":"IPC-BO","login":"a","password":"p"},{"name":"IPC-BO (2)","login":"a","password":"p"},
 {"name":"XR","login":"a","password":"p"},{"name":"C110","login":"a","password":"p"},{"name":"HDIPC","login":"a","password":"p"}]'
mkdir -p "$fx/d1"; echo keep >"$fx/d1/.hidden"
"$here/stream_soak.sh" "$fx/d1" 1 >/dev/null 2>&1; rc=$?
check "stream_soak: refuses dir with only a dotfile" '[[ $rc != 0 && ! -e $fx/d1/summary.tsv ]]'
ln -s "$fx/d1" "$fx/l1"
"$here/stream_soak.sh" "$fx/l1" 1 >/dev/null 2>&1; rc=$?
check "stream_soak: refuses symlink to non-empty dir" '[[ $rc != 0 && ! -e $fx/d1/summary.tsv ]]'
echo x >"$fx/f1"
"$here/stream_soak.sh" "$fx/f1" 1 >/dev/null 2>&1; rc=$?
check "stream_soak: refuses a regular file" '[[ $rc != 0 && $(cat "$fx/f1") == x ]]'
mkdir -p "$fx/d2"; echo old >"$fx/d2/summary.tsv"; chmod 300 "$fx/d2"
"$here/stream_soak.sh" "$fx/d2" 1 >/dev/null 2>&1; rc=$?; chmod 700 "$fx/d2"
check "stream_soak: refuses non-empty dir it cannot list (mode 0300)" '[[ $rc != 0 && $(cat "$fx/d2/summary.tsv") == old ]]'
"$here/stream_soak.sh" "$fx/new" 1 >/dev/null 2>&1; rc=$?
check "stream_soak: summary has a row per stream when streams yield no frames" '[[ $rc == 0 && $(wc -l <"$fx/new/summary.tsv") == 11 ]]'

exit "$fail"
