"""Check UDP worker reuse with a running Auth101 and default example credentials."""

import argparse
from pathlib import Path
import signal
import subprocess
import tempfile
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", type=Path, required=True)
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
                 "--workers", "1"],
                cwd=build, stdout=output, stderr=subprocess.STDOUT,
            )
            try:
                deadline = time.monotonic() + 15
                while "UDP server ready" not in log.read_text():
                    if server.poll() is not None or time.monotonic() >= deadline:
                        raise RuntimeError("UDP server failed to become ready")
                    time.sleep(0.1)

                for attempt in range(2):
                    client = subprocess.run(
                        [str(build / "client"), str(configs / "client_udp.config"),
                         str(csv)],
                        cwd=build, capture_output=True, text=True, timeout=30,
                    )
                    if client.returncode != 0:
                        raise RuntimeError(client.stdout + client.stderr)
                    if "Successfully finished communication" not in client.stdout:
                        raise RuntimeError("UDP client did not complete its session")
                    print(f"UDP client {attempt + 1} completed", flush=True)
                    if attempt == 0:
                        # The server releases an idle session after ten seconds.
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
    print("UDP worker reuse smoke test passed")


if __name__ == "__main__":
    main()
