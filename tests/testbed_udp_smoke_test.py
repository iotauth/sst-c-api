"""Check UDP worker reuse or concurrent handshakes with Auth101 running."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import signal
import subprocess
import tempfile
import time


def run_client(build, configs, csv, attempt):
    client = subprocess.run(
        [str(build / "client"), str(configs / "client_udp.config"), str(csv)],
        cwd=build, capture_output=True, text=True, timeout=30, check=False,
    )
    if client.returncode != 0:
        raise RuntimeError(client.stdout + client.stderr)
    if "Successfully finished communication" not in client.stdout:
        raise RuntimeError("UDP client did not complete its session")
    print(f"UDP client {attempt + 1} completed", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", type=Path, required=True)
    parser.add_argument("--concurrent", action="store_true",
                        help="Use two workers and start both clients together")
    args = parser.parse_args()
    build = args.build_dir.resolve()
    configs = Path(__file__).resolve().parents[1] / "examples/SST_Testbed/config"

    with tempfile.TemporaryDirectory(prefix="udp-smoke-", dir=build) as directory:
        directory = Path(directory)
        csv = directory / "messages.csv"
        csv.write_text("0,UDP worker reuse smoke test\n")
        log = directory / "server.log"
        with log.open("w") as output:
            server = subprocess.Popen(
                [str(build / "server"), str(configs / "server_udp.config"),
                 "--workers", "2" if args.concurrent else "1"],
                cwd=build, stdout=output, stderr=subprocess.STDOUT,
            )
            try:
                deadline = time.monotonic() + 15
                while "UDP server ready" not in log.read_text():
                    if server.poll() is not None or time.monotonic() >= deadline:
                        raise RuntimeError("UDP server failed to become ready")
                    time.sleep(0.1)

                if args.concurrent:
                    with ThreadPoolExecutor(max_workers=2) as pool:
                        futures = [pool.submit(run_client, build, configs, csv, i)
                                   for i in range(2)]
                        for future in futures:
                            future.result()
                else:
                    for attempt in range(2):
                        run_client(build, configs, csv, attempt)
                        if attempt == 0:
                            # Let the first session expire before reusing its worker.
                            time.sleep(12)
            except Exception:
                print(log.read_text(), flush=True)
                raise
            finally:
                if server.poll() is None:
                    server.send_signal(signal.SIGINT)
                    try:
                        server.wait(timeout=15)
                    except subprocess.TimeoutExpired:
                        server.kill()
                        server.wait()
            if server.returncode != 0:
                raise RuntimeError("UDP server failed to shut down:\n" + log.read_text())
        # Verify delivery, not just successful client-side sends.
        if log.read_text().count("UDP worker reuse smoke test") != 2:
            raise RuntimeError("The server did not receive both messages:\n" + log.read_text())
    print("UDP concurrent handshake smoke test passed" if args.concurrent
          else "UDP worker reuse smoke test passed")


if __name__ == "__main__":
    main()
