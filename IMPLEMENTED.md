# IMPLEMENTED.md — IPsec VPN Analyzer Backend

Status snapshot of the backend build against `CLAUDE.md`'s milestone plan
(M0–M7) and `PHASE2.md`'s Observer Profile plan (M8). Branch:
`claude/backend-plan-claude-md-l3m6gc`.

Everything below marked **Verified** was actually run and passed in this
environment. Everything marked **Written, not verified** compiles/parses
correctly and follows the documented spec it targets, but could not be
executed here (no Docker / no privileged networking) — it needs to be run
locally before you rely on it for a demo.

## What's done

| Milestone | What | Status |
|---|---|---|
| M0 | Repo scaffold, FastAPI skeleton, `/health`, SQLite wiring | Verified |
| M1 | strongSwan testbed: docker-compose, 6 `ipsec.conf` variants, traffic generator, capture script | Written, not verified |
| M2 | tshark-backed IKE parser (`app/ike/parser.py`) | Verified |
| M3 | ESP flow feature extractor (`app/flow/extractor.py`) | Verified |
| M4 | Dataset builder + RandomForest classifier training (`app/ml/`) | Verified (pipeline mechanics only — see caveat below) |
| M5 | Scoring engine + YAML policy (`app/scoring/`) | Verified |
| M6 | Full REST API wired into `app/main.py` | Verified |
| M7 | Technical/executive reports, error handling | Verified |
| M8 | Observer Profile: metadata exposure decoupled from `overall_score`, `app/observer/` (profile/correlate/render), tunnel-linked sessions, 4 new endpoints | Verified |

34/34 pytest tests pass (`cd backend && pytest -q`).

## Phase 2: Observer Profile (M8)

Per `PHASE2.md`. `overall_score` is now computed from `crypto_strength`,
`compliance`, and `key_management` only — `metadata_exposure` is still on
`ScoreResult` but is never blended in, so a tunnel really can score A+ on
crypto and F on metadata exposure at once (see
`tests/test_scoring_engine.py::test_metadata_exposure_never_affects_overall_score`
and the full-pipeline regression in
`tests/test_observer_api.py::test_core_thesis_strong_crypto_high_metadata_exposure`,
which builds a hand-crafted strong IKEv2 handshake + a confidently-classified
VoIP-shaped ESP flow, uploads it through the real API, and asserts
`overall_score > 85` and `metadata_exposure < 40` on the same session).

`Session` gained `tunnel_id`/`peer_label` (user-settable via
`PATCH /sessions/{id}`) plus `peer_src_ip`/`peer_dst_ip`, read from the
capture's first IP packet during `/analyze` (a small, deliberate addition —
needed to make `peer_stability` findings real rather than fake). Single-flow
findings (`traffic_identifiability`, `padding_exposure`) come from
`app/observer/profile.py`; multi-session findings (`temporal_pattern`,
`peer_stability`, `volume_signature`, or an explicit `insufficient_history`
object below 2 sessions) come from `app/observer/correlate.py`. New
endpoints: `GET /sessions/{id}/observer-profile`,
`GET /tunnels/{tunnel_id}/observer-profile` (both `?format=json|markdown`),
and `PATCH /sessions/{id}`.

M9 (drift detection across sessions) was not started, per PHASE2.md's own
instruction to only begin it once M8 is fully tested.

## API surface (all live at `http://localhost:8000`)

```
GET    /health
POST   /sessions/upload            multipart pcap upload -> Session
GET    /sessions                   list sessions
GET    /sessions/{id}              session detail
PATCH  /sessions/{id}              set tunnel_id / peer_label
POST   /sessions/{id}/analyze      run IKE parsing + flow extraction + classification
GET    /sessions/{id}/ike          IkeFinding
GET    /sessions/{id}/flows        list of FlowFinding
GET    /sessions/{id}/score        ScoreResult (?policy_id= to score against a custom policy)
GET    /sessions/{id}/report       ?type=technical|executive & ?format=json|markdown
GET    /sessions/{id}/observer-profile      ?format=json|markdown
GET    /tunnels/{tunnel_id}/observer-profile  aggregated, multi-session
POST   /policy                     upload a custom compliance policy YAML
GET    /policy/{id}
```

Interactive docs: `http://localhost:8000/docs`.

## What was actually verified, and how

- **IKE parser (M2):** tshark's default `-T json` output silently drops
  sibling fields that share a name — my first draft's field names were
  wrong because of this. I installed tshark in this environment, hand-built
  RFC-correct IKEv1 Main Mode and IKEv2 IKE_SA_INIT packets byte-for-byte
  (`tests/fixtures/generate_fixtures.py`), decoded them with
  `tshark -T json --no-duplicate-keys`, and rewrote the parser against the
  real field names and tree shape. Those two packets are checked in as
  `tests/fixtures/*.pcap` and covered by `tests/test_ike_parser.py`.
- **Flow extractor (M3):** unit-tested against a synthetic ESP pcap built
  with Scapy (`tests/test_flow_extractor.py`).
- **Scoring engine (M5):** unit-tested against a strong config (AES-GCM-256/
  ECP-384/PFS-on, scores >85, zero threats) and a weak one (DES/MD5/
  MODP-768/PFS-off, scores <30, multiple threats) — `tests/test_scoring_engine.py`.
- **ML pipeline (M4):** dataset build → train → classify round-tripped
  end-to-end on synthetic labeled ESP traffic (`tests/test_ml_pipeline.py`).
  **This proves the wiring works, not that the classifier is accurate** —
  see caveat below.
- **Full API (M6/M7):** `tests/test_api_end_to_end.py` and
  `tests/test_policy_and_errors.py` walk upload → analyze → ike → flows →
  score → report (both formats), plus error paths (bad upload, missing
  session, score/report requested before analysis, malformed policy YAML,
  non-IKE pcap). Also manually exercised against a synthetic demo pcap over
  real HTTP — see transcript in this conversation's history.

## Known gaps / what still needs you

1. **The testbed itself is unverified.** `backend/testbed/` (docker-compose,
   the 6 `ipsec.conf` variants, `generate_traffic.py`, `capture.sh`) is
   written against strongSwan's documented config syntax and standard
   Compose networking, but this sandbox has no Docker. Bring it up locally
   (`backend/testbed/README.md` has the exact steps) and tell me what
   breaks — LAN routing between the two simulated hosts through the
   gateways is the most likely rough edge.

2. **No trained classifier yet.** There is no real labeled traffic to train
   on, so `app/ml/artifacts/` is empty and `/sessions/{id}/flows` will
   report every flow as `"unknown"` confidence `0.0` until you run the
   testbed, generate traffic across all 5 classes (icmp/web/voip/video/
   email) and all 6 config variants, then run:
   ```
   python -m app.ml.dataset
   python -m app.ml.train
   ```
   This is deliberate, not a bug — the classifier fails closed instead of
   pretending to have learned something it hasn't.

3. **IKEv1 Phase 2 (Quick Mode / ESP) parsing is written but not
   independently fixture-tested** the way Phase 1 and IKEv2 are — only
   IKEv1 Main Mode and IKEv2 IKE_SA_INIT got hand-built RFC packets. Worth
   a fixture once you have a real IKEv1 capture with PFS enabled in Phase 2.

4. **IPv6 config variant** (`tunnel_aesgcm256_dh20_pfson_ipv6.conf`) needs
   an IPv6-enabled Docker network added to `docker-compose.yml` — the file
   says so in its header comment; it's not wired into the compose file as
   checked in.

## Repo layout

See `CLAUDE.md` for the full directory contract and build order this was
built against. Nothing in it was deviated from.
