"""Drives labeled traffic between alice-host and bob-host through the tunnel.

Each traffic type produces a metadata pattern (packet size/timing) distinct
enough for app/flow/extractor.py + the ML classifier to learn from -- the
point isn't protocol-correctness, it's producing realistic side-channel
shapes on the ESP-encapsulated wire.

Run alongside testbed/scripts/capture.sh, e.g.:

    python generate_traffic.py --traffic voip --duration 20 &
    ./capture.sh tunnel_aesgcm256_dh19_pfson_ipv4 voip 25
    wait
"""

import argparse
import shlex
import subprocess
import time

ALICE_HOST = "alice-host"
BOB_HOST = "bob-host"
BOB_LAN_IP = "10.0.2.10"


def _exec(container: str, command: str, background: bool = False) -> subprocess.Popen | None:
    full_cmd = ["docker", "exec"] + (["-d"] if background else []) + [container, "sh", "-c", command]
    if background:
        return subprocess.Popen(full_cmd)
    subprocess.run(full_cmd, check=True)
    return None


def generate_icmp(duration: int) -> None:
    count = max(1, duration * 20)  # ~20 pings/sec
    _exec(ALICE_HOST, f"ping -c {count} -i 0.05 {BOB_LAN_IP} >/dev/null 2>&1")


def generate_web(duration: int) -> None:
    server = _exec(BOB_HOST, "python3 -m http.server 8080", background=True)
    time.sleep(1)
    try:
        script = (
            f"end=$(($(date +%s)+{duration})); "
            f"while [ $(date +%s) -lt $end ]; do "
            f"curl -s http://{BOB_LAN_IP}:8080/ -o /dev/null; "
            f"sleep 0.$((RANDOM % 5 + 1)); "
            f"done"
        )
        _exec(ALICE_HOST, script)
    finally:
        if server:
            server.terminate()
        # bracket-obfuscated so this cleanup command's own argv (which
        # necessarily contains its search string too) doesn't self-match
        # and get killed by its own pkill before reaching "|| true"
        _exec(BOB_HOST, "pkill -f 'http.serv[e]r' || true")


_UDP_SENDER = """
import socket, time, sys, random
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
dst = (sys.argv[1], int(sys.argv[2]))
duration = float(sys.argv[3])
mode = sys.argv[4]
start = time.time()
while time.time() - start < duration:
    if mode == "voip":
        payload = b"x" * 160          # ~G.711 20ms frame size
        sock.sendto(payload, dst)
        time.sleep(0.02)
    elif mode == "video":
        size = random.choice([1400, 1400, 1400, 600])  # bursty, mostly MTU-sized
        sock.sendto(b"x" * size, dst)
        time.sleep(0.005 if size == 1400 else 0.02)
    elif mode == "email":
        sock.sendto(b"x" * random.randint(800, 4000), dst)
        time.sleep(random.uniform(0.5, 2.0))
    elif mode == "messaging":
        # Approximation of a WhatsApp-style messaging app's known public
        # traffic characteristics (small bursty message packets + periodic
        # keepalives), NOT a real captured messaging protocol -- see
        # testbed/README.md and docs/dataset_card.md for why this can't be
        # the real thing in an isolated lab. Keepalive interval is compressed
        # to 5s (real apps use ~30-60s) so it's actually observable within a
        # short demo capture; this is a deliberate simplification, not a bug.
        for _ in range(random.randint(1, 3)):
            sock.sendto(b"x" * random.randint(80, 300), dst)
            time.sleep(random.uniform(0.05, 0.3))
        sock.sendto(b"k" * 40, dst)  # keepalive
        time.sleep(random.uniform(1.0, 5.0))
sock.close()
"""


def _run_udp_pattern(mode: str, duration: int, port: int) -> None:
    listener = _exec(BOB_HOST, f"python3 -c \"import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(('0.0.0.0',{port})); [s.recvfrom(4096) for _ in iter(int, 1)]\"", background=True)
    time.sleep(1)
    try:
        script = f"python3 -c {shlex.quote(_UDP_SENDER)} {BOB_LAN_IP} {port} {duration} {mode}"
        _exec(ALICE_HOST, script)
    finally:
        if listener:
            listener.terminate()
        # same self-match issue as the http.server cleanup above
        _exec(BOB_HOST, "pkill -f 'socket.SOCK_DGRA[M]' || true")


def generate_voip(duration: int) -> None:
    _run_udp_pattern("voip", duration, port=17000)


def generate_video(duration: int) -> None:
    _run_udp_pattern("video", duration, port=17001)


def generate_email(duration: int) -> None:
    _run_udp_pattern("email", duration, port=17002)


def generate_messaging(duration: int) -> None:
    """Approximated "messaging app" traffic (see _UDP_SENDER's messaging
    branch) -- NOT real WhatsApp traffic, which can't be captured in an
    isolated lab with no internet egress or real client pairing.
    """
    _run_udp_pattern("messaging", duration, port=17003)


GENERATORS = {
    "icmp": generate_icmp,
    "web": generate_web,
    "voip": generate_voip,
    "video": generate_video,
    "email": generate_email,
    "messaging": generate_messaging,
}


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate labeled traffic through the testbed tunnel")
    parser.add_argument(
        "--config",
        default=None,
        help="informational only: which ipsec.conf variant is active "
        "(applied separately via apply_config.sh) -- used for log output and "
        "to help you name the matching capture.sh invocation",
    )
    parser.add_argument("--traffic", choices=sorted(GENERATORS), default="icmp")
    parser.add_argument("--duration", type=int, default=20, help="seconds of traffic to generate")
    args = parser.parse_args()

    if args.config:
        print(f"Active config (informational): {args.config}")
    print(f"Generating {args.duration}s of {args.traffic} traffic alice-host -> bob-host ...")
    GENERATORS[args.traffic](args.duration)
    print("Done.")


if __name__ == "__main__":
    main()
