#!/usr/bin/env python3
"""한길 인사·근태 관리 서버 (사내망 전용)

- 파이썬 3.8 이상 표준 라이브러리만 사용합니다 (추가 설치 없음).
- 사내 IP(사설 대역)에서 온 접속만 받고, 그 밖의 주소는 403으로 거절합니다.
- 인사 데이터는 브라우저에서 AES-256-GCM으로 암호화된 뒤 전송·저장됩니다.
  이 서버는 암호문만 보관하며 비밀번호나 복호화 키를 알지 못합니다.

실행:  python server.py            (기본 포트 8080)
       python server.py --port 9000 --allow 192.168.0.0/24
"""
import argparse
import hashlib
import hmac
import ipaddress
import json
import mimetypes
import os
import shutil
import sys
import threading
import time
from datetime import datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "static")

DEFAULT_ALLOW = [
    "127.0.0.0/8", "::1/128",          # 서버 PC 자신
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",  # 사설 IPv4 대역
    "fc00::/7", "fe80::/10",            # 사설·링크로컬 IPv6
]
KDF = {"alg": "PBKDF2-SHA256", "c": 120000, "dkLen": 64}
MAX_BODY = 20 * 1024 * 1024
KEEP_BACKUPS = 300
FAIL_LIMIT = 5

LOCK = threading.Lock()
FAILS = {}  # ip -> [연속 실패 횟수, 차단 해제 시각]


def now_iso():
    return datetime.now().isoformat(timespec="seconds")


class Store:
    def __init__(self, data_dir):
        self.dir = os.path.abspath(data_dir)
        self.backup_dir = os.path.join(self.dir, "backups")
        os.makedirs(self.backup_dir, exist_ok=True)
        self.meta_path = os.path.join(self.dir, "meta.json")
        self.vault_path = os.path.join(self.dir, "vault.json")

    def _read(self, path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except FileNotFoundError:
            return None

    def _write(self, path, obj):
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(obj, f, ensure_ascii=False)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)

    def meta(self):
        return self._read(self.meta_path)

    def vault(self):
        return self._read(self.vault_path)

    def backup_current(self):
        v = self.vault()
        if not v:
            return
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        dst = os.path.join(self.backup_dir, f"vault-{stamp}-v{v.get('version', 0)}.json")
        shutil.copyfile(self.vault_path, dst)
        files = sorted(f for f in os.listdir(self.backup_dir) if f.startswith("vault-"))
        for old in files[:-KEEP_BACKUPS]:
            try:
                os.remove(os.path.join(self.backup_dir, old))
            except OSError:
                pass

    def init(self, salt, auth_hex, box, ip):
        self._write(self.meta_path, {"salt": salt, "auth_hash": sha_hex(auth_hex), "kdf": KDF, "created": now_iso()})
        self._write(self.vault_path, {"version": 1, "box": box, "updated": now_iso(), "by": ip})

    def put(self, box, ip):
        cur = self.vault() or {"version": 0}
        self.backup_current()
        new = {"version": int(cur.get("version", 0)) + 1, "box": box, "updated": now_iso(), "by": ip}
        self._write(self.vault_path, new)
        return new

    def rekey(self, salt, auth_hex, box, ip):
        self.backup_current()
        meta = self.meta() or {}
        meta.update({"salt": salt, "auth_hash": sha_hex(auth_hex), "kdf": KDF, "rekeyed": now_iso()})
        cur = self.vault() or {"version": 0}
        self._write(self.meta_path, meta)
        new = {"version": int(cur.get("version", 0)) + 1, "box": box, "updated": now_iso(), "by": ip}
        self._write(self.vault_path, new)
        return new

    def reset(self):
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        keep = os.path.join(self.dir, f"reset-{stamp}")
        os.makedirs(keep, exist_ok=True)
        for p in (self.meta_path, self.vault_path):
            if os.path.exists(p):
                shutil.move(p, os.path.join(keep, os.path.basename(p)))


def sha_hex(auth_hex):
    return hashlib.sha256(bytes.fromhex(auth_hex)).hexdigest()


def valid_hex(s, n):
    if not isinstance(s, str) or len(s) != n:
        return False
    try:
        bytes.fromhex(s)
        return True
    except ValueError:
        return False


def valid_box(box):
    return (isinstance(box, dict) and isinstance(box.get("iv"), str) and isinstance(box.get("ct"), str)
            and 0 < len(box["iv"]) <= 64 and 0 < len(box["ct"]) <= MAX_BODY)


class Handler(BaseHTTPRequestHandler):
    server_version = "HangilHR"
    sys_version = ""
    networks = []
    store = None

    # ---------- 공통 ----------
    def client_ip(self):
        ip = ipaddress.ip_address(self.client_address[0])
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        return ip

    def allowed(self):
        ip = self.client_ip()
        return any(ip in net for net in self.networks)

    def is_local(self):
        return self.client_ip().is_loopback

    def log_message(self, fmt, *args):
        sys.stderr.write("[%s] %s %s\n" % (now_iso(), self.client_address[0], fmt % args))

    def security_headers(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        self.send_header("Content-Security-Policy",
                         "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
                         "img-src 'self' data: blob:; connect-src 'self'; font-src 'self'; "
                         "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")

    def send_json(self, code, obj):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.security_headers()
        self.end_headers()
        self.wfile.write(body)

    def deny(self):
        self.log_message("거절됨(사내망 아님): %s %s", self.command, self.path)
        body = "사내 네트워크에서만 접속할 수 있습니다.".encode("utf-8")
        self.send_response(HTTPStatus.FORBIDDEN)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def read_json(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n <= 0 or n > MAX_BODY:
            return None
        try:
            return json.loads(self.rfile.read(n).decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return None

    def same_origin(self):
        # 다른 사이트가 사내 PC의 브라우저를 이용해 요청을 보내는 것(CSRF)을 막는다.
        origin = self.headers.get("Origin")
        if not origin:
            return True
        host = self.headers.get("Host", "")
        return urlsplit(origin).netloc == host

    def check_auth(self):
        """X-HR-Auth 헤더 검사. 실패가 반복되면 일정 시간 차단."""
        ip = str(self.client_ip())
        with LOCK:
            fails, until = FAILS.get(ip, [0, 0])
            if until > time.time():
                self.send_json(429, {"error": "locked", "retry": int(until - time.time()) + 1})
                return False
        meta = self.store.meta()
        token = self.headers.get("X-HR-Auth", "")
        ok = bool(meta) and valid_hex(token, 64) and hmac.compare_digest(sha_hex(token), meta.get("auth_hash", ""))
        with LOCK:
            if ok:
                FAILS.pop(ip, None)
            else:
                fails += 1
                wait = 0 if fails < FAIL_LIMIT else min(60 * 2 ** (fails - FAIL_LIMIT), 3600)
                FAILS[ip] = [fails, time.time() + wait]
        if not ok:
            self.send_json(401, {"error": "auth"})
        return ok

    # ---------- 라우팅 ----------
    def do_GET(self):
        if not self.allowed():
            return self.deny()
        path = urlsplit(self.path).path
        if path == "/api/meta":
            meta = self.store.meta()
            return self.send_json(200, {
                "initialized": bool(meta),
                "salt": meta.get("salt") if meta else None,
                "kdf": meta.get("kdf", KDF) if meta else KDF,
                "local": self.is_local(),
            })
        if path == "/api/vault":
            if not self.check_auth():
                return
            return self.send_json(200, self.store.vault() or {"version": 0, "box": None})
        if path == "/api/version":
            if not self.check_auth():
                return
            v = self.store.vault() or {}
            return self.send_json(200, {"version": v.get("version", 0), "updated": v.get("updated")})
        return self.serve_static(path)

    def do_HEAD(self):
        if not self.allowed():
            return self.deny()
        return self.serve_static(urlsplit(self.path).path, head=True)

    def do_POST(self):
        if not self.allowed():
            return self.deny()
        if not self.same_origin():
            return self.send_json(403, {"error": "origin"})
        path = urlsplit(self.path).path
        if path == "/api/init":
            data = self.read_json()
            if not data or not valid_hex(data.get("auth"), 64) or not valid_box(data.get("box")) \
                    or not isinstance(data.get("salt"), str) or len(data["salt"]) > 64:
                return self.send_json(400, {"error": "bad request"})
            with LOCK:
                if self.store.meta():
                    return self.send_json(409, {"error": "already initialized"})
                self.store.init(data["salt"], data["auth"], data["box"], str(self.client_ip()))
            self.log_message("데이터 저장소 초기화")
            return self.send_json(200, {"version": 1})
        if path == "/api/rekey":
            if not self.check_auth():
                return
            data = self.read_json()
            if not data or not valid_hex(data.get("auth"), 64) or not valid_box(data.get("box")) \
                    or not isinstance(data.get("salt"), str):
                return self.send_json(400, {"error": "bad request"})
            with LOCK:
                cur = self.store.vault() or {"version": 0}
                if data.get("base") != cur.get("version"):
                    return self.send_json(409, {"error": "conflict", "version": cur.get("version")})
                new = self.store.rekey(data["salt"], data["auth"], data["box"], str(self.client_ip()))
            self.log_message("비밀번호 변경")
            return self.send_json(200, {"version": new["version"]})
        if path == "/api/reset":
            # 비밀번호를 잊었을 때: 서버 PC 자신(localhost)에서만 허용
            if not self.is_local():
                return self.send_json(403, {"error": "local only"})
            data = self.read_json() or {}
            if data.get("confirm") != "초기화":
                return self.send_json(400, {"error": "confirm"})
            with LOCK:
                self.store.reset()
            self.log_message("데이터 저장소 초기화(리셋) - 이전 파일은 data/reset-* 에 보관")
            return self.send_json(200, {"ok": True})
        return self.send_json(404, {"error": "not found"})

    def do_PUT(self):
        if not self.allowed():
            return self.deny()
        if not self.same_origin():
            return self.send_json(403, {"error": "origin"})
        if urlsplit(self.path).path != "/api/vault":
            return self.send_json(404, {"error": "not found"})
        if not self.check_auth():
            return
        data = self.read_json()
        if not data or not valid_box(data.get("box")):
            return self.send_json(400, {"error": "bad request"})
        with LOCK:
            cur = self.store.vault() or {"version": 0}
            if data.get("base") != cur.get("version"):
                return self.send_json(409, {"error": "conflict", "version": cur.get("version")})
            new = self.store.put(data["box"], str(self.client_ip()))
        return self.send_json(200, {"version": new["version"], "updated": new["updated"]})

    def serve_static(self, path, head=False):
        if path in ("", "/"):
            path = "/index.html"
        full = os.path.realpath(os.path.join(STATIC_DIR, path.lstrip("/")))
        if not full.startswith(os.path.realpath(STATIC_DIR) + os.sep) or not os.path.isfile(full):
            return self.send_json(404, {"error": "not found"})
        ctype = mimetypes.guess_type(full)[0] or "application/octet-stream"
        if ctype.startswith("text/") or ctype in ("application/javascript", "text/javascript"):
            ctype += "; charset=utf-8"
        with open(full, "rb") as f:
            body = f.read()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-cache")
        self.security_headers()
        self.end_headers()
        if not head:
            self.wfile.write(body)


class Server(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, addr, handler):
        if ":" in addr[0]:
            import socket
            self.address_family = socket.AF_INET6
        super().__init__(addr, handler)


def load_config():
    path = os.path.join(BASE_DIR, "config.json")
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}


def main():
    cfg = load_config()
    ap = argparse.ArgumentParser(description="한길 인사·근태 관리 서버 (사내망 전용)")
    ap.add_argument("--host", default=cfg.get("host", "0.0.0.0"), help="수신 주소 (기본 0.0.0.0)")
    ap.add_argument("--port", type=int, default=cfg.get("port", 8080), help="포트 (기본 8080)")
    ap.add_argument("--data", default=cfg.get("data", os.path.join(BASE_DIR, "data")), help="데이터 폴더")
    ap.add_argument("--allow", default=",".join(cfg.get("allow", DEFAULT_ALLOW)),
                    help="접속 허용 대역(쉼표 구분). 예: 192.168.0.0/24")
    args = ap.parse_args()

    nets = [ipaddress.ip_network(x.strip(), strict=False) for x in args.allow.split(",") if x.strip()]
    for n in nets:
        if not (n.is_private or n.is_loopback or n.is_link_local):
            sys.exit(f"[오류] 공인 IP 대역은 허용할 수 없습니다: {n}")
    loop = [n for n in nets if n.version == 4 and ipaddress.ip_address("127.0.0.1") in n]
    if not loop:
        nets.append(ipaddress.ip_network("127.0.0.0/8"))

    Handler.networks = nets
    Handler.store = Store(args.data)
    mimetypes.add_type("application/javascript", ".js")
    mimetypes.add_type("text/css", ".css")

    httpd = Server((args.host, args.port), Handler)
    print("=" * 60)
    print(" 한길 인사·근태 관리 서버 (사내망 전용)")
    print(f" 서버 PC에서:   http://localhost:{args.port}")
    try:
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("10.255.255.255", 1))
        print(f" 사내 다른 PC:  http://{s.getsockname()[0]}:{args.port}")
        s.close()
    except OSError:
        pass
    print(f" 허용 대역: {', '.join(str(n) for n in nets)}")
    print(f" 데이터 폴더: {Handler.store.dir}")
    print(" 종료: Ctrl+C")
    print("=" * 60)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n서버를 종료합니다.")


if __name__ == "__main__":
    main()
