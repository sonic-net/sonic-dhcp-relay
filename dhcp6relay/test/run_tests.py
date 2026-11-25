#!/usr/bin/env python3
"""Run the DHCPv6 tests against a private, temporary Redis instance."""

import argparse
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time


def stop(process):
    if process is not None and process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def wait_ready(server, path):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if server.poll() is not None:
            raise RuntimeError("private Redis exited before becoming ready")
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.settimeout(0.1)
                client.connect(str(path))
                client.sendall(b"PING\r\n")
                if client.recv(64) == b"+PONG\r\n":
                    return
        except OSError:
            pass
        time.sleep(0.05)
    raise RuntimeError("private Redis did not become ready within 5 seconds")


def run(command, redis_server):
    with tempfile.TemporaryDirectory(prefix="dhcp6relay-test-") as directory:
        root = Path(directory)
        socket_path = root / "redis.sock"
        config = json.loads(Path(__file__).with_name("database_config.json").read_text())
        config["INSTANCES"]["redis"]["unix_socket_path"] = str(socket_path)
        config_path = root / "database_config.json"
        config_path.write_text(json.dumps(config))
        environment = dict(os.environ, DHCP6RELAY_TEST_DATABASE_CONFIG=str(config_path))
        server = test = None
        try:
            # No TCP listener, persistence, global configuration or shared database.
            server = subprocess.Popen([
                redis_server, "--port", "0", "--unixsocket", str(socket_path),
                "--unixsocketperm", "700", "--save", "", "--appendonly", "no",
                "--dir", directory, "--daemonize", "no",
            ])
            wait_ready(server, socket_path)
            test = subprocess.Popen(command, env=environment)
            result = test.wait()
            if server.poll() is not None:
                raise RuntimeError("private Redis exited while tests were running")
            return result if result >= 0 else 128 - result
        finally:
            stop(test)
            stop(server)


def interrupted(signum, _frame):
    raise SystemExit(128 + signum)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--redis-server", default="redis-server")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        parser.error("a test command is required after --")
    for signum in (signal.SIGINT, signal.SIGTERM):
        signal.signal(signum, interrupted)
    try:
        return run(command, args.redis_server)
    except (OSError, RuntimeError) as error:
        print(f"DHCPv6 test fixture: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
