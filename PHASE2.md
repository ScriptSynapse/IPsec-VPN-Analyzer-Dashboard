PHASE2.md — Observer Profile & Metadata Exposure
Builds on the implemented backend in `CLAUDE.md`/`IMPLEMENTED.md` (M0–M7 done, 20/20 tests passing). This phase does not touch the IKE parser, flow extractor, or classifier — it adds a new interpretation layer on top of data those modules already produce. No new ML model. No new packet parsing beyond what's already extracted.
Why this phase exists
A rule-based compliance score answers "is this config strong." It cannot answer "what can an observer actually learn from this tunnel regardless of how strong the config is" — that requires looking at flow classifier confidence and timing patterns, which the pipeline already computes but currently only uses to build `overall_score`. This phase surfaces that data as its own first-class output: the Observer Profile. The target demo moment is a tunnel that scores A+ on crypto and F on metadata exposure — that split is the whole point, so the scoring architecture has to actually allow it (see below).
Required change to `ScoreResult` — read before implementing
Currently `metadata_exposure` is one of four category scores that get blended into `overall_score`. Averaging it in dilutes the exact contradiction this phase exists to surface. Change `app/scoring/engine.py` so:

* `overall_score` is computed from `crypto_strength`, `compliance`, and `key_management` only (technical posture).
* `metadata_exposure` is still returned on `ScoreResult`, but reported as an independent headline figure, never averaged into `overall_score`.

Update `tests/test_scoring_engine.py`'s strong/weak fixtures to assert this explicitly — add a case where crypto posture is strong but metadata exposure is high, and assert `overall_score` stays high while `metadata_exposure` doesn't.
Data model changes
`Session` gains:

* `tunnel_id: str | None` — user-supplied label to group multiple captures of the same monitored tunnel over time. Without it, a session is analyzed alone.
* `peer_label: str | None` — optional human-readable name for the peer pair.

New schema, `ObserverFinding`:

```
category      : "traffic_identifiability" | "padding_exposure"
              | "temporal_pattern" | "peer_stability" | "volume_signature"
description   : str   # plain-language, judge-readable
confidence    : float  # 0-1
evidence      : dict   # the raw stats backing the claim
mitigation    : str

```

`temporal_pattern`, `peer_stability`, and `volume_signature` require 2+ sessions sharing a `tunnel_id`. With fewer, emit a single explicit `{"category": "insufficient_history", "sessions_needed": 2, "sessions_have": N}` object rather than silently omitting the section — the report should never look like the feature is broken.
New modules

```
app/observer/
  profile.py     # single-session findings: traffic_identifiability, padding_exposure
  correlate.py   # multi-session findings, given 2+ sessions sharing a tunnel_id
  render.py      # markdown renderer for the Observer Profile report

```

`traffic_identifiability` — for each `FlowFinding`, if classifier confidence exceeds a threshold (default 0.75), emit a finding: what traffic type was identified, at what confidence, purely from size/timing — no decryption involved. This is a direct read of data `app/ml/classifier.py` already produces.
`padding_exposure` — ESP supports optional TFC (Traffic Flow Confidentiality) padding specifically to mask true payload sizes; it's rarely enabled in practice. You can't observe whether TFC padding was negotiated directly, but you already compute packet-size variance per flow in `app/flow/features.py` — use it as a heuristic: low size variance suggests padding-like behavior (good), high variance correlated with a classified traffic type (e.g. VoIP-like periodicity) suggests no padding is in effect (bad). Report this as a heuristic, not a certainty — say so in the finding text.
`temporal_pattern` / `peer_stability` / `volume_signature` (in `correlate.py`, needs 2+ sessions with the same `tunnel_id`) — cluster session start times (consistent time-of-day → recurring pattern), check whether the peer IP pair stays constant across sessions, check whether session duration/ byte volume for a given predicted traffic type stays consistent. These are descriptive statistics over data you already have, not new inference.
API additions

```
PATCH  /sessions/{id}                    { tunnel_id?, peer_label? }
GET    /sessions/{id}/observer-profile   ?format=json|markdown
GET    /tunnels/{tunnel_id}/observer-profile     aggregated, multi-session
GET    /tunnels/{tunnel_id}/drift                stretch — see M9 below

```

Build order

* M8.1 — data model migration: add `tunnel_id`/`peer_label` to `Session`; decouple `metadata_exposure` from `overall_score` in the scoring engine; update existing tests per the note above before writing anything new.
* M8.2 — `observer/profile.py`: single-session findings (`traffic_identifiability`, `padding_exposure`).
* M8.3 — `observer/correlate.py`: multi-session findings, with the explicit "insufficient history" fallback when `tunnel_id` has fewer than 2 sessions.
* M8.4 — wire the four API endpoints, add `render.py` markdown output.
* M8.5 — tests: synthetic fixtures with 1 session (confirms insufficient-history path), and with 3 sessions sharing a `tunnel_id` at consistent times/peer/volume (confirms recurrence findings actually fire). Include one fixture that's strong on crypto and high on metadata exposure — this is the regression test for the core thesis of this phase.

Stretch — M9: drift detection
Not required for the demo to work, but the natural next layer once M8 lands: compare `IkeFinding`s across ordered sessions sharing a `tunnel_id` and flag downgrades — cipher weakens, DH group drops, PFS toggles off, SA lifetime lengthens unexpectedly on rekey. `app/drift/detector.py`, one new endpoint (`GET /tunnels/{tunnel_id}/drift`). Only start this after M8 is fully tested.
Non-goals

* No new ML model or retraining requirement — this phase is a read layer over existing outputs.
* No attempt to infer literal content, only pattern/metadata-level exposure.
* No change to the IKE parser or flow extractor internals.

Demo note
The report that matters most out of this phase is a single session where `overall_score` is high (strong crypto, PFS on, good DH group) and `metadata_exposure` is low (i.e., bad) because a flow was identified as VoIP at
90% confidence with a recognizable duration pattern. That contradiction is the one-sentence pitch: compliant does not mean private, and this is the only part of the platform that can prove it.
