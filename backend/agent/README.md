# Monitoring Agent

A lightweight process for an **authorized** remote machine (e.g. a
teammate's PC, a gateway you have permission to monitor). It captures
IKE/ESP traffic locally in rolling chunks and uploads each chunk to the
analyzer backend as a new Session, so the dashboard's Tunnel / Observer
Profile view gets real, time-spread data instead of one-off manual
uploads.

**Only run this against traffic you're authorized to monitor.** It's a
packet-capture tool -- treat it with the same care you'd give `tcpdump`
itself, because that's literally what it wraps.

## 1. Register the agent (once, from anywhere that can reach the backend)

```bash
curl -X POST http://<backend-host>:8000/agents \
    -H 'Content-Type: application/json' \
    -d '{"name": "member-pc-1"}'
```

Response:
```json
{"id": "...", "name": "member-pc-1", "api_key": "..."}
```

**Save `id` and `api_key` now.** The key is a one-time secret, generated
and shown exactly once -- the backend only ever stores a hash of it, per
`app/agent/auth.py`, and there is no "forgot my key" recovery. If you lose
it, register a new agent.

## 2. Run the agent (on the authorized remote machine)

```bash
cd backend/agent
pip install -r requirements.txt

python agent.py \
    --backend-url http://<backend-host>:8000 \
    --agent-id <id-from-step-1> \
    --api-key <key-from-step-1> \
    --interface eth0 \
    --tunnel-id office-tunnel \
    --peer-label "HQ <-> Branch"
```

- `--interface` is whichever interface actually sees the IKE/ESP traffic
  you want monitored -- usually needs the same privileges `tcpdump` itself
  would need (root, or `sudo setcap cap_net_raw,cap_net_admin+eip
  $(which tcpdump)` once, so the agent doesn't need to run as root).
- `--tunnel-id` is what ties this agent's captures together into one
  Tunnel in the dashboard, and (if a second agent or manual upload shares
  the same tunnel_id) is what makes multi-session correlation
  (`peer_stability`, `temporal_pattern`, `volume_signature`) start
  producing real findings instead of `insufficient_history`.
- `--chunk-seconds` (default 300) controls how often a chunk gets uploaded.
  Shorter = more responsive dashboard updates and smaller per-upload risk
  if the connection drops mid-capture; longer = fewer, larger uploads.

The agent runs until stopped (Ctrl+C / SIGTERM), capturing continuously:
finish one chunk, upload it, immediately start the next. If a chunk fails
to upload (backend unreachable), it's kept on disk under `--workdir` and
retried automatically once capture resumes -- nothing is silently dropped,
though a long backend outage will accumulate chunks on disk.

## Running it long-term (systemd example)

```ini
[Unit]
Description=IPsec VPN Analyzer monitoring agent
After=network-online.target

[Service]
ExecStart=/usr/bin/python3 /path/to/backend/agent/agent.py \
    --backend-url http://<backend-host>:8000 \
    --agent-id <id> --api-key <key> \
    --interface eth0 --tunnel-id office-tunnel
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
```

## What this does *not* do

- It does not decrypt anything -- it captures the same IKE/ESP traffic
  `tcpdump` would, nothing more.
- It does not scan the network or discover other hosts -- it only captures
  on the one interface you point it at, with the BPF filter you give it.
- It is not authentication for the *backend* API generally -- there's no
  broader user auth model yet (see `app/main.py`'s CORS comment); the
  agent key only proves "this upload/heartbeat came from a registered
  agent," matching PATCH/GET endpoints remain open, same as before agents
  existed. Don't expose the backend beyond a trusted network.
