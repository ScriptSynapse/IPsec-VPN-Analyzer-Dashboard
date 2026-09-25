# IMPLEMENTED-PHASE2.md — Observer Profile & Metadata Exposure

Status snapshot of `PHASE2.md`'s build (M8). Branch:
`claude/backend-plan-claude-md-l3m6gc`, commit `dd1b449`. Builds on the
M0–M7 backend documented in `IMPLEMENTED.md`.

Unlike Phase 1's testbed piece, everything in this phase is pure Python/DB
logic — no Docker, no privileged networking required — so everything below
is **Verified**: actually run and passed in this environment, and
additionally manually exercised over live HTTP by the user against a
running `uvicorn` instance (see this conversation's transcript).

## What's done

| Milestone | What | Status |
|---|---|---|
| M8.1 | `Session` gains `tunnel_id`/`peer_label`/`peer_src_ip`/`peer_dst_ip`; `overall_score` decoupled from `metadata_exposure` in `app/scoring/engine.py` | Verified |
| M8.2 | `app/observer/profile.py` — single-session findings: `traffic_identifiability`, `padding_exposure` | Verified |
| M8.3 | `app/observer/correlate.py` — multi-session findings: `temporal_pattern`, `peer_stability`, `volume_signature`, or `insufficient_history` below 2 sessions | Verified |
| M8.4 | `app/observer/render.py` + 4 new/changed endpoints wired into `app/main.py` | Verified |
| M8.5 | Tests: 1-session insufficient-history path, 3-session recurrence, core-thesis regression | Verified |

34/34 pytest tests pass (`cd backend && pytest -q`).

## The core architectural change

`overall_score` in `ScoreResult` now comes from `crypto_strength` +
`compliance` + `key_management` only. `metadata_exposure` is still on
`ScoreResult`, but is never averaged in — it's reported as an independent
headline figure. This is what makes it possible for a tunnel to score A+ on
crypto and F on metadata exposure at the same time, which is the one-line
pitch this whole phase exists to prove.

Proven two ways:
- `tests/test_scoring_engine.py::test_metadata_exposure_never_affects_overall_score`
  — same handshake, two different classifier confidences, identical
  `overall_score`, different `metadata_exposure`.
- `tests/test_observer_api.py::test_core_thesis_strong_crypto_high_metadata_exposure`
  — a hand-crafted strong IKEv2 handshake (AES-CBC-256/HMAC-SHA2-384/
  ECP-384, PFS on via a Child SA DH transform) paired with a VoIP-shaped ESP
  flow, run through a classifier trained inline on synthetic traffic,
  uploaded through the real HTTP API end to end. Asserts `overall_score >
  85` and `metadata_exposure < 40` on the same session.
- Manually re-confirmed live by the user against a running server: see the
  "did this work at all?" walkthrough in this conversation, where a
  synthetic demo pcap was uploaded twice under the same `tunnel_id` and
  produced a real `insufficient_history` → `temporal_pattern`/
  `peer_stability` transition once the 2-session threshold was crossed.

## New/changed data model

`Session` gained:
- `tunnel_id: str | None` — user-set via `PATCH /sessions/{id}`, groups
  captures of the same monitored tunnel over time.
- `peer_label: str | None` — user-set, human-readable name for the peer pair.
- `peer_src_ip` / `peer_dst_ip: str | None` — **not** user-set; read from the
  capture's first IP packet during `/analyze` (`app/utils/pcap_io.py:get_first_packet_ips`).
  This is a small, deliberate addition beyond PHASE2.md's literal "no new
  packet parsing" — without real peer IPs, `peer_stability` would have
  nothing real to check and would be fake. The IKE parser and flow extractor
  themselves were not touched.

`FlowFinding` gained `std_packet_size` (packet-size standard deviation),
already computed by `app/flow/extractor.py` but not previously persisted —
needed for the `padding_exposure` heuristic.

## New modules

```
app/observer/
  profile.py     # traffic_identifiability, padding_exposure (single session)
  correlate.py   # temporal_pattern, peer_stability, volume_signature (2+ sessions)
  render.py      # markdown renderer
```

Both `profile.py` and `correlate.py` return plain dataclasses (mirroring the
existing `ThreatMatrixEntry` pattern in `app/scoring/engine.py`), converted
to dicts at the API layer — not strict pydantic response models, since the
finding list is heterogeneously shaped (an `insufficient_history` object has
a different shape than a real finding).

## API additions

```
PATCH  /sessions/{id}                        { tunnel_id?, peer_label? }
GET    /sessions/{id}/observer-profile       ?format=json|markdown
GET    /tunnels/{tunnel_id}/observer-profile  aggregated, multi-session
```

(`GET /tunnels/{tunnel_id}/drift` — the M9 stretch goal — was not started,
per PHASE2.md's own instruction to only begin it once M8 is fully tested.)

## A gotcha hit during manual verification (not a code bug)

Upgrading a checked-out repo in place, on top of an **existing**
`backend/data/app.db` from before this phase, throws
`sqlite3.OperationalError: table sessions has no column named tunnel_id` on
the first upload. This is expected: SQLAlchemy's `Base.metadata.create_all()`
(called from `init_db()`) only creates missing tables, it never alters
existing ones to add new columns — there's no migration framework in this
project (SQLite was chosen for scope reasons per `CLAUDE.md`, and a fresh
demo environment never hits this). Fix is to delete the stale db file and
let it recreate: `rm backend/data/app.db` before restarting `uvicorn`. If
this project moves past pure-demo scope, this is the point where a real
migration tool (Alembic) would need to be introduced — not done here since
it's out of scope for both `CLAUDE.md` and `PHASE2.md`.

## Known gaps

- `volume_signature` needs at least 2 sessions with the *same* classified
  traffic type to say anything — with only 1 flow per session (as in the
  synthetic demo pcap used above), it silently contributes nothing to
  `findings` rather than a placeholder object, unlike `insufficient_history`
  which explicitly does. Worth revisiting if this asymmetry ever confuses a
  demo audience.
- No drift detection yet (M9, explicitly deferred).
