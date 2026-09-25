#!/usr/bin/env python3
"""IPsec VPN Analyzer monitoring agent.

Runs on an authorized machine that can see the IKE/ESP traffic you want
monitored (e.g. a gateway, or a host on the same segment as one). Captures
traffic in rolling chunks and uploads each chunk to the analyzer backend as
a new Session, tagged with this agent's identity and (optionally) a
tunnel_id so multiple agents/captures of the same real tunnel correlate in
the dashboard's Tunnel / Observer Profile view.

Deliberately dependency-light (only `requests`) so it can be dropped onto a
teammate's machine without installing this whole project there. Capture
itself shells out to the system `tcpdump` rather than reimplementing packet
capture -- one less thing to get subtly wrong, same reasoning as the
testbed's capture.sh.

Usage:
    python agent.py --backend-url http://<backend-host>:8000 \\
        --agent-id <id> --api-key <key> \\
        --interface eth0 --tunnel-id office-tunnel

Register an agent first (on the backend host, or anywhere that can reach
it) to get <id>/<key> -- see README.md in this directory.
"""

import argparse
import logging
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import requests

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("ipsec-analyzer-agent")

_shutdown_requested = False


def _handle_signal(signum, _frame) -> None:
    global _shutdown_requested
    log.info("received signal %s, finishing current chunk then exiting", signum)
    _shutdown_requested = True


def send_heartbeat(session: requests.Session, backend_url: str, agent_id: str, api_key: str) -> None:
    try:
        resp = session.post(
            f"{backend_url}/agents/{agent_id}/heartbeat",
            headers={"X-Agent-Key": api_key},
            timeout=10,
        )
        if resp.status_code == 401:
            log.error("heartbeat rejected: invalid agent id or api key -- check registration")
        elif not resp.ok:
            log.warning("heartbeat failed: HTTP %s", resp.status_code)
    except requests.RequestException as exc:
        log.warning("heartbeat failed: %s (backend unreachable?)", exc)


class CaptureError(Exception):
    """tcpdump failed outright (bad interface, no permission, ...) --
    distinct from "ran fine but nothing matched the filter", which is a
    normal, expected outcome and not an error.
    """


def capture_chunk(interface: str, duration_s: int, bpf_filter: str, out_path: Path) -> bool:
    """Runs tcpdump for duration_s seconds. Returns True if it produced a
    non-empty capture, False if it ran successfully but nothing matched.
    Raises CaptureError if tcpdump itself failed (e.g. permission denied) --
    caught by the run() loop, which backs off instead of retrying in a
    tight loop (a real bug this had at first: a permission error makes
    tcpdump exit almost instantly, and with no distinction from "clean
    empty capture" the loop spun at full speed instead of every
    duration_s seconds).
    """
    cmd = ["timeout", str(duration_s), "tcpdump", "-i", interface, "-w", str(out_path), bpf_filter]
    log.info("capturing on %s for %ss -> %s", interface, duration_s, out_path.name)
    started = time.monotonic()
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=duration_s + 15)
    except subprocess.TimeoutExpired as exc:
        raise CaptureError("tcpdump did not exit within the expected window") from exc
    elapsed = time.monotonic() - started

    # `timeout N cmd` exits 124 if it had to kill cmd at the deadline (the
    # expected, successful case for a full-duration capture) and passes
    # through cmd's own exit code otherwise. tcpdump failing outright
    # (bad interface, no permission) exits near-instantly with a non-124,
    # non-zero code -- that combination is the real failure to catch.
    if result.returncode not in (0, 124) and elapsed < duration_s * 0.5:
        stderr = result.stderr.strip() or "(no stderr output)"
        raise CaptureError(f"tcpdump exited immediately (code {result.returncode}): {stderr}")

    if not out_path.exists() or out_path.stat().st_size <= 24:  # 24 bytes = empty pcap global header only
        log.info("no packets captured this chunk (nothing matched %r on %s)", bpf_filter, interface)
        return False
    return True


def upload_chunk(
    session: requests.Session,
    backend_url: str,
    agent_id: str,
    api_key: str,
    pcap_path: Path,
    tunnel_id: str | None,
    peer_label: str | None,
) -> bool:
    data = {}
    if tunnel_id:
        data["tunnel_id"] = tunnel_id
    if peer_label:
        data["peer_label"] = peer_label

    try:
        with open(pcap_path, "rb") as f:
            resp = session.post(
                f"{backend_url}/sessions/upload",
                headers={"X-Agent-Id": agent_id, "X-Agent-Key": api_key},
                data=data,
                files={"file": (pcap_path.name, f, "application/vnd.tcpdump.pcap")},
                timeout=60,
            )
    except requests.RequestException as exc:
        log.warning("upload failed: %s (backend unreachable? chunk kept locally for retry)", exc)
        return False

    if resp.status_code == 201:
        log.info("uploaded %s -> session %s", pcap_path.name, resp.json().get("id"))
        return True
    if resp.status_code == 401:
        log.error("upload rejected: invalid agent id or api key -- check registration, not retrying")
        return True  # don't keep retrying a chunk that will never be accepted
    log.warning("upload failed: HTTP %s %s", resp.status_code, resp.text[:200])
    return False


def run(args: argparse.Namespace) -> None:
    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    session = requests.Session()
    workdir = Path(args.workdir)
    workdir.mkdir(parents=True, exist_ok=True)

    log.info("agent starting: backend=%s interface=%s chunk=%ss tunnel_id=%s",
             args.backend_url, args.interface, args.chunk_seconds, args.tunnel_id)
    send_heartbeat(session, args.backend_url, args.agent_id, args.api_key)

    consecutive_capture_errors = 0
    while not _shutdown_requested:
        chunk_path = workdir / f"chunk_{int(time.time())}.pcap"
        try:
            got_packets = capture_chunk(args.interface, args.chunk_seconds, args.bpf_filter, chunk_path)
            consecutive_capture_errors = 0
        except CaptureError as exc:
            consecutive_capture_errors += 1
            backoff_s = min(60, 5 * consecutive_capture_errors)
            log.error("capture failed (%s) -- retrying in %ss. Check --interface and that "
                      "tcpdump has permission to capture on it (run as root, or "
                      "`sudo setcap cap_net_raw,cap_net_admin+eip $(which tcpdump)`).",
                      exc, backoff_s)
            chunk_path.unlink(missing_ok=True)
            for _ in range(backoff_s):
                if _shutdown_requested:
                    break
                time.sleep(1)
            continue

        if got_packets:
            uploaded = upload_chunk(
                session, args.backend_url, args.agent_id, args.api_key,
                chunk_path, args.tunnel_id, args.peer_label,
            )
            if uploaded:
                chunk_path.unlink(missing_ok=True)
            else:
                log.info("keeping %s on disk for the next retry pass", chunk_path.name)
        else:
            chunk_path.unlink(missing_ok=True)

        send_heartbeat(session, args.backend_url, args.agent_id, args.api_key)

    log.info("shut down cleanly")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--backend-url", required=True, help="e.g. http://192.168.1.10:8000")
    parser.add_argument("--agent-id", required=True)
    parser.add_argument("--api-key", required=True)
    parser.add_argument("--interface", required=True, help="network interface to capture on, e.g. eth0")
    parser.add_argument("--tunnel-id", default=None, help="groups this agent's captures into one Tunnel")
    parser.add_argument("--peer-label", default=None, help="human label shown in the dashboard for this tunnel")
    parser.add_argument("--chunk-seconds", type=int, default=300, help="capture duration per uploaded chunk")
    parser.add_argument(
        "--bpf-filter", default="udp port 500 or udp port 4500 or esp",
        help="tcpdump filter -- default captures IKE control traffic + ESP only",
    )
    parser.add_argument("--workdir", default=tempfile.gettempdir() + "/ipsec-analyzer-agent")
    args = parser.parse_args()

    try:
        run(args)
    except KeyboardInterrupt:
        sys.exit(0)


if __name__ == "__main__":
    main()
