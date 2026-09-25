# Technical Documentation — IPsec VPN Analyzer

**Target PS:** AI-Powered IPsec VPN Protocol Analyzer and Security Assessment
Framework (NTRO — Blockchain & Cybersecurity theme, cybersecurity half only).

This document is written for judges and reviewers. It leads with the single
distinction that matters most for evaluating whether this is real security
engineering or "AI" bolted onto a parser for show.

---

## 1. The one distinction that decides whether this is real

There are two fundamentally different kinds of "detection" in this system,
and they must never be blurred:

1. **Deterministic parsing.** IKE Phase 1/2 proposals — cipher, DH group,
   PFS flag, auth method, IKE version — are transmitted in **cleartext**
   during the handshake. This is a parsing problem, solved with tshark's
   mature ISAKMP dissector. Training a model to predict a field that is
   already sitting in the packet as plaintext would be strictly worse than
   parsing it, and would be exactly the kind of "fake AI" this problem
   statement exists to filter out.
2. **ML classification.** Only the traffic type riding inside encrypted ESP
   packets (VoIP / web / video / email / ICMP / messaging) genuinely cannot
   be read directly. This is inferred from flow-level side-channel features
   — packet size distribution, inter-arrival timing, burst pattern, flow
   duration — never from payload content. This is the actual AI component.

**ESP payloads are never decrypted, anywhere in this system.** All ESP-layer
inference comes from observable metadata only. This is a security
assessment tool, not a decryption tool.

---

## 2. Architecture

```
                     ┌─────────────────────────┐
                     │   Testbed (Docker)      │
                     │  strongSwan peer A/B    │
                     │  + traffic generators    │
                     └──────────┬──────────────┘
                                │ tcpdump
                                ▼
                     labeled .pcap files (data/pcaps/)
                                │
              ┌─────────────────┼─────────────────┐
              ▼                                    ▼
      IKE Parser (tshark)                Flow Feature Extractor (Scapy)
      → cipher/DH/PFS/auth/IKEver         → per-ESP-flow stats
              │                                    │
              ▼                                    ▼
      IkeFinding (DB)                    FlowFinding + traffic-type
                                          classifier (RandomForest)
              │                                    │
              └────────────────┬───────────────────┘
                                ▼
                       Scoring Engine (rules.py)
                       → category scores + overall score + threat matrix
                                │
                                ▼
                   Observer Profile (metadata exposure, read layer)
                                │
                                ▼
                   Reports (Executive + Technical, JSON/MD)
                                │
                                ▼
                    FastAPI REST API  ──────►  React Dashboard (Vite)
```

Full request/response contract: [`API-SPEC.md`](../API-SPEC.md).

---

## 3. IKE parser (`backend/app/ike/parser.py`)

Subprocess into `tshark -r <pcap> -Y "isakmp" -T json --no-duplicate-keys`
and walk the resulting JSON tree. The `--no-duplicate-keys` flag matters:
tshark's default `-T json` output silently **drops sibling fields that share
a field name** (confirmed empirically — see below), which corrupts
multi-transform proposals if you don't ask for it explicitly.

Handles both IKE versions with separate code paths, since the wire format
genuinely differs:
- **IKEv2**: typed transform fields (`isakmp.tf.type` / `isakmp.tf.id.encr`
  / `.integ` / `.dh`), used for both the IKE_SA_INIT proposal and any
  Child SA (`CREATE_CHILD_SA`) proposal. A DH transform present in a Child
  SA proposal (protocol ID = ESP) is what determines `pfs_enabled`.
- **IKEv1**: Phase 1 (ISAKMP) proposals encode algorithms as SA attributes
  (`isakmp.ike.attr.encryption_algorithm`, `.hash_algorithm`,
  `.group_description`, `.life_duration`); Phase 2 (Quick Mode / ESP)
  proposals encode the encryption algorithm directly as the Transform ID
  (`isakmp.trans.id`) per RFC 2407, with auth/DH/lifetime as separate
  `isakmp.ipsec.attr.*` attributes.

**Field-name correctness was verified empirically, not assumed.** tshark
was installed and used to decode two hand-built, RFC-correct packets — an
IKEv1 Main Mode proposal and an IKEv2 IKE_SA_INIT proposal, built byte-for-
byte from the RFC 2409 / RFC 7296 wire formats (`backend/tests/fixtures/
generate_fixtures.py`) — and the parser was written against the real
decoded JSON, not documentation guesses. Those two pcaps are checked in as
fixtures and covered by `tests/test_ike_parser.py`.

**Known gap:** IKEv1 Phase 2 (Quick Mode / ESP) parsing is written against
the RFC 2407 transform/attribute registries but has no independent
hand-built fixture the way Phase 1 and IKEv2 do — worth adding once a real
IKEv1 capture with PFS enabled in Phase 2 exists.

### Algorithm/DH-group scoring tables live in the scoring engine, not here

The parser only extracts names (`"AES-GCM-16"`, `"ECP-384"`, etc.) from
numeric IDs via the IANA transform registries. It assigns no scores and
makes no security judgments — that's the scoring engine's job (§6).

---

## 4. Flow feature extractor (`backend/app/flow/extractor.py`)

Groups ESP packets by `(src, dst, spi)` — ESP has no ports, so SPI stands
in for the transport-layer identifier — and computes, per flow:

| Feature | What it captures |
|---|---|
| `packet_count`, `duration_s` | flow size/length |
| `avg_packet_size`, `std_packet_size`, `min/max_packet_size` | size distribution |
| `avg_inter_arrival_ms`, `std_inter_arrival_ms` | timing distribution |
| `bytes_per_second`, `packets_per_second` | throughput |
| `burstiness` | Goh & Barabási's burstiness parameter, `(σ-μ)/(σ+μ)` over inter-arrival times |
| `seq_gap_ratio` | fraction of non-consecutive ESP sequence numbers (RFC 4303's sequence number field is cleartext) |

Every one of these comes from headers and timing an on-path observer would
see regardless of encryption strength — none of it requires or attempts
decryption.

---

## 5. ML traffic-type classifier (`backend/app/ml/`)

**Model:** RandomForestClassifier — chosen deliberately over a black-box
model because the problem statement asks for an "AI Confidence Score," and
a model with `feature_importances_` can have that confidence justified in
front of judges rather than asserted.

**Pipeline:** `dataset.py` walks `data/pcaps/`, runs the flow extractor on
each capture, and parses the ground-truth traffic-type label directly from
the filename (`{mode}_{cipher}_{dh}_{pfs}_{iptype}_{traffic}_{timestamp}.pcap`
— see §7). `train.py` trains RandomForest and evaluates on a held-out split.
`classifier.py` loads the saved artifact and exposes
`predict(features) -> (traffic_type, confidence)`, where confidence is the
model's `predict_proba` output for the predicted class.

**Split methodology:** train/test splitting is **grouped by source pcap**
(`sklearn.model_selection.GroupShuffleSplit`), not by row. Splitting by row
would let flows from the same capture appear on both sides of the split,
inflating apparent accuracy through leakage — the split is designed
specifically to prevent that.

**Fail-closed by design:** if no model artifact has been trained yet,
`classifier.predict()` returns `("unknown", 0.0)` rather than crashing or
fabricating a guess. This is intentional, not a bug — a fresh checkout with
no testbed captures should still serve every API endpoint.

**Current status, stated plainly:** as of this document, the testbed has
not been run in a live Docker environment (see §7's caveat), so there is no
real trained baseline classifier checked in, and no real accuracy/confusion
matrix to report yet. `backend/tests/test_ml_pipeline.py` proves the
dataset→train→classify wiring is correct end-to-end using synthetic ESP
traffic, but synthetic data proves the pipeline works, not that the
classifier is accurate on real traffic. **Do not present a synthetic result
as a real accuracy number to judges.** Once the testbed is run and produces
real captures, re-run `python -m app.ml.dataset && python -m app.ml.train`
and report the actual classification report it prints.

---

## 6. Scoring engine (`backend/app/scoring/`)

Every score traces to a named rule in `app/scoring/rules.py`. The weight
tables are aligned with the algorithm tiers in **RFC 8221** (Cryptographic
Algorithm Implementation Requirements for ESP/AH — MUST / SHOULD / SHOULD
NOT / MUST NOT) and the minimum key-strength guidance in **NIST SP 800-77
Rev.1** (Guide to IPsec VPNs).

> **Citation caveat, stated honestly:** this documentation was written
> without live access to the RFC/NIST source text at the time of writing.
> The relative ordering (AEAD > CBC > legacy ciphers; SHA-2 > SHA-1 > MD5;
> EC/large MODP > small MODP) reflects well-established, defensible
> cryptographic consensus, and each score's docstring names the source
> document. **Verify exact section numbers and wording against the actual
> RFC 8221 / NIST SP 800-77 text before citing specific clauses to judges.**

### Category scores

| Category | What it measures | Key inputs |
|---|---|---|
| `crypto_strength` | Weighted blend of encryption (50%), auth/integrity (30%), DH group (20%) algorithm strength | `ENCRYPTION_SCORES`, `AUTH_SCORES`, `DH_GROUP_SCORES` in `rules.py` |
| `compliance` | % of policy checks passed (encryption/auth minimums, banned algorithms, PFS requirement, max SA lifetime) against the active `CryptoPolicy` | `app/scoring/policy.py`, `engine.py::_compliance` |
| `key_management` | Average of DH group score, lifetime score, and a PFS on/off component | `engine.py::_key_management` |
| `metadata_exposure` | Derived from the ML classifier's average confidence across flows — **not part of `overall_score`**, see below | `engine.py::_metadata_exposure` |

`overall_score` is a weighted sum of **`crypto_strength` + `compliance` +
`key_management` only** (45% / 30% / 25%, `OVERALL_WEIGHTS` in `rules.py`).
`metadata_exposure` is deliberately excluded from this sum and reported as
an independent headline figure instead — see §8, this is the entire point
of the Observer Profile phase.

### Mapping against a broader six-category breakdown

An earlier planning pass (`PLAN.md` §M5) proposed six weighted categories:
crypto strength, key exchange, PFS, IKE version, auth method, lifetime,
replay protection, and metadata exposure. The implemented four-category
model folds several of these together rather than implementing them as
separate top-level weights:

- **PFS** and **lifetime** are folded into `key_management`, not weighted
  separately, since both are properties of key-management practice.
- **IKE version** and **auth method** penalties are expressed as
  `compliance` policy checks (banned-algorithm / minimum-score checks)
  rather than separate category scores.
- **Replay protection** was deliberately **not implemented** as a scoring
  category. Anti-replay window size/presence is a local kernel Security
  Policy Database (SPD) setting on each IPsec peer, not something
  negotiated over the wire in an ISAKMP field tshark reliably decodes as a
  distinct, observable value across implementations. Adding a fabricated
  "replay protection score" without a reliable observable signal would
  violate this project's own rule that every score must trace to a named,
  real rule — so it was left out rather than faked. If a reliable signal
  is found later (e.g. consistently present ESN transform negotiation as a
  proxy), this is the place to add it.

### Threat matrix + custom policy

Every failed `compliance` check appends a
`{finding, likelihood, impact, recommendation}` entry to the threat matrix
(`ThreatMatrixEntry` in `engine.py`). A confidently-classified flow
(`metadata_exposure < 40`) adds one more, tying the ML classifier's own
success directly to a security finding: if the model can reliably guess
traffic type from metadata, that itself is evidence worth reporting.

Users can upload a custom YAML policy (`POST /policy`) overriding minimum
scores, banned algorithms, PFS requirement, max SA lifetime, and category
weights — see [`API-SPEC.md`](../API-SPEC.md#post-policy) for the schema.

---

## 7. VPN testbed (`backend/testbed/`)

A representative 17-config matrix (not the full combinatorial explosion)
spanning tunnel/transport mode, IKEv1/IKEv2, AEAD and legacy ciphers, PFS
on/off, and IPv4/IPv6 — including two deliberately weak configs (3DES/
MODP-768 and AES-128/SHA-1/MODP-1024) so the scoring engine and demo have
something real to catch. Full table: `backend/testbed/README.md`.

Traffic generators cover ICMP, web, VoIP, video, email, and messaging.

**The "messaging" traffic type is an explicit approximation, not real
captured traffic.** A real WhatsApp-style app cannot be captured in an
isolated lab testbed with no internet egress and no real client pairing.
`messaging` instead generates small bursty packets plus a periodic
keepalive tuned to WhatsApp's publicly known traffic characteristics. This
is documented, not silently faked — see `docs/dataset_card.md` and
`backend/testbed/README.md`. **State this plainly if a judge asks whether
the "messaging" class is real WhatsApp traffic: it is not.**

**Caveat carried over from earlier builds:** the testbed (docker-compose,
strongSwan configs, traffic generators) has been written carefully against
strongSwan's documented `ipsec.conf` syntax and standard Docker Compose
networking, but has not been exercised in a live Docker environment during
this build — the build sandbox has no Docker or privileged networking.
Validate it locally before relying on it for a live demo; see
`backend/testbed/README.md` for exact steps and known rough edges (LAN
routing between the simulated hosts through the gateways is the most
likely one).

---

## 8. Observer Profile — metadata exposure as a first-class output

A rule-based compliance score answers "is this config strong." It cannot
answer "what can a passive observer actually learn from this tunnel
regardless of how strong the config is" — that requires looking at
classifier confidence and session-to-session patterns, which the pipeline
already computes but would otherwise only feed into one blended number.

This is why `overall_score` and `metadata_exposure` are architecturally
separate (§6): **a tunnel can score A+ on crypto and F on metadata exposure
at the same time**, and the scoring model has to actually allow that split
rather than average it away.

- **Single-session findings** (`app/observer/profile.py`):
  `traffic_identifiability` (a flow was confidently fingerprinted as a
  specific traffic type from size/timing alone) and `padding_exposure` (a
  packet-size-variance heuristic for whether ESP TFC padding looks like
  it's in effect — explicitly labeled as a heuristic, since the TFC padding
  negotiation flag itself isn't observable on the wire).
- **Multi-session findings** (`app/observer/correlate.py`), once 2+
  sessions share a user-set `tunnel_id`: `temporal_pattern` (recurring
  time-of-day activity), `peer_stability` (does the peer IP pair stay
  constant), `volume_signature` (is byte volume per traffic type
  consistent across sessions). Below 2 sessions, an explicit
  `insufficient_history` object is returned instead of silently omitting
  the section.

Endpoints: `GET /sessions/{id}/observer-profile`,
`GET /tunnels/{tunnel_id}/observer-profile` (both `?format=json|markdown`).

This was proven end-to-end, not just described: a hand-crafted strong
IKEv2 handshake (AES-CBC-256 / HMAC-SHA2-384 / ECP-384, PFS on via a Child
SA DH transform) combined with a VoIP-shaped ESP flow, run through a
classifier trained inline on synthetic traffic, uploaded through the real
HTTP API — asserting `overall_score > 85` and `metadata_exposure < 40` on
the same session (`tests/test_observer_api.py::test_core_thesis_strong_crypto_high_metadata_exposure`).

---

## 9. Dashboard (`frontend/`)

A Vite + React + Tailwind v4 SPA, a thin client over the REST API — no
analysis logic lives in it, every number and finding comes from the
backend. (An earlier Streamlit version covered the same ground faster to
build; it was fully replaced at the user's request once a more polished
multi-page design was wanted.)

Pages: `/sessions` (list + upload), `/sessions/:id` (the main view — IKE
handshake table, ESP flow classification with confidence, score breakdown
+ threat matrix, Observer Profile findings, technical/executive report
viewer with markdown download), `/tunnels` + `/tunnels/:tunnelId`
(multi-session correlation), `/policies` (upload/inspect custom scoring
policies), `/reports` (quick links into each session's report). The
backend has permissive CORS enabled (`app/main.py`) so the dashboard can
run on a different port without a dev-server proxy.

Verified end-to-end during this build: booted both the API and the
dashboard, drove real uploads through the dashboard's own file-upload
widget with headless Playwright across every page, tagged two sessions
into the same `tunnel_id` and confirmed the `insufficient_history` ->
`temporal_pattern`/`peer_stability` transition fired correctly, toggled
the report type and policy upload flows, and fixed one real bug caught
this way (a same-render-tick race in the shared data-fetching hook that
could momentarily render a stale, differently-shaped report object when
switching technical/executive report type, before its query dependency
finished re-fetching — see `frontend/src/components/ReportPanel.jsx`'s
`"risk_band" in report` guard).

---

## 10. Known limitations, stated plainly

1. **Testbed unverified in a live Docker environment** (see §7).
2. **No real trained classifier baseline** — the checked-in ML pipeline is
   proven correct on synthetic data only; a real baseline requires running
   the testbed first (see §5).
3. **"Messaging" traffic is an approximation**, not real captured WhatsApp
   traffic (see §7).
4. **The analysis pipeline is synchronous** (`/sessions/{id}/analyze` runs
   IKE parsing + flow extraction + classification in-request). Fine at
   hackathon demo scale; a production version would queue this async so a
   large pcap doesn't block the request.
5. **IKEv1 Phase 2 parsing has no independent hand-built fixture** the way
   Phase 1 and IKEv2 do (§3).
6. **Replay protection is not scored** — deliberately, not by oversight
   (§6).
7. **Drift detection (comparing IKE findings across ordered sessions in the
   same tunnel to flag downgrades) is not implemented** — planned as a
   stretch goal (`PHASE2.md`'s M9) once the Observer Profile itself was
   fully tested, and not started as of this document.

---

## 11. Anticipated judge Q&A

1. **"Why isn't the crypto algorithm itself ML-predicted?"** Because it's
   cleartext in the handshake; predicting it with ML would be strictly
   worse than parsing it, and pretending otherwise is exactly the kind of
   "fake AI" this problem statement is designed to filter out.
2. **"How do you classify traffic without decrypting it?"** Side-channel
   flow features only (size/timing/burst pattern) — the same family of
   technique used in encrypted-traffic classification research generally,
   not a novel decryption method. ESP payloads are never touched.
3. **"What's your model's actual accuracy, and on what test set?"** Have
   the real classification report from `python -m app.ml.train` ready,
   generated after running the testbed — not a number from this document,
   and not the synthetic-data test fixture's numbers (see §5, §10.2).
4. **"Is 'messaging' traffic really WhatsApp?"** No — it's an explicit
   approximation given lab constraints (no internet egress, no real client
   pairing), tuned to WhatsApp's publicly known traffic shape. Say so
   plainly (§7, §10.3).
5. **"Why does `overall_score` not include metadata exposure?"** Because
   averaging it in would hide the exact contradiction the Observer Profile
   exists to prove — that a technically compliant config can still leak
   everything through metadata. See §8.
