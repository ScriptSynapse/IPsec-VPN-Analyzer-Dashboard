# CLAUDE.md — IPsec VPN Analyzer Backend

## Project context

This is the backend for SIH26160: an AI-driven platform that analyzes IPsec VPN
deployments (captured or live traffic), identifies protocol/config characteristics,
runs an automated security assessment, and produces reports. Organization: NTRO.
Theme: Blockchain & Cybersecurity (cybersecurity half only — no blockchain
requirement in this PS despite the theme name).

This file governs backend work only. Frontend/dashboard is a separate phase — the
backend must expose a clean REST API that a frontend can consume later without
backend changes.

## Read this before writing any code

There are two fundamentally different kinds of "detection" in this system. Do not
blur them.

1. **Deterministic parsing** — IKE Phase 1/2 proposals (cipher, DH group, PFS
   flag, auth method, IKE version) are transmitted in cleartext during the
   handshake. This is a parsing problem. Extract it directly from the payload
   fields. Do not train a model to predict something that is already sitting in
   the packet as plaintext — that's fake AI and will fall apart under judge
   scrutiny.
2. **ML classification** — Only what genuinely cannot be read directly, i.e. the
   type of traffic riding inside encrypted ESP packets (VoIP / web / video /
   email / ICMP), is inferred from flow-level side-channel features (packet
   size distribution, inter-arrival timing, burst pattern, flow duration).
   This is the actual AI component and where model quality matters.

**Never attempt to decrypt ESP payloads.** All ESP-layer inference must come from
observable metadata only (sizes, timing, headers, sequence numbers) — this is a
security assessment tool, not a decryption tool, and treating it otherwise breaks
the entire premise of the problem statement.

## Tech stack

- Python 3.11+
- FastAPI + uvicorn (API layer)
- SQLite + SQLAlchemy (session/findings/score storage — sufficient for this scope)
- Pydantic v2 (schemas/validation)
- Scapy (packet crafting for testbed traffic, ESP/IP header-level feature extraction)
- tshark, invoked via subprocess with `-T json` (IKE payload parsing — use its
  mature dissectors rather than hand-rolling IKEv1/v2 payload parsing)
- pandas (feature dataframes)
- scikit-learn + xgboost (traffic-type classifier)
- joblib (model persistence)
- pytest (tests)

Do not introduce a different web framework, ORM, or ML library without a strong
reason — consistency matters more than optimality here given the timeline.

## Directory structure

```
backend/
  app/
    main.py                    # FastAPI app entrypoint, router registration
    core/
      config.py                # settings (paths, DB url, model paths)
      db.py                    # SQLAlchemy engine/session
      schemas.py               # shared pydantic models (Session, Finding, Score)
    api/
      routes_capture.py        # upload pcap, list/get sessions
      routes_analysis.py       # trigger analysis, get findings
      routes_scoring.py        # get score, upload custom policy
      routes_reports.py        # get executive/technical report
    ike/
      parser.py                # tshark subprocess wrapper -> structured IKE fields
      schemas.py                # IkeHandshake, SaProposal models
    flow/
      extractor.py             # per-flow feature extraction from ESP packets (Scapy)
      features.py                # feature name constants, column schema
    ml/
      dataset.py                # build labeled dataset from data/datasets/
      train.py                  # training script, saves to ml/artifacts/
      classifier.py              # load model, predict + confidence
      artifacts/                 # saved .joblib models (gitignored except a
                                  # checked-in baseline for demo reliability)
    scoring/
      rules.py                  # crypto/DH/PFS/lifetime weight tables (NIST SP
                                  # 800-77 / RFC 8221 aligned — cite source in
                                  # comments, don't hardcode magic numbers unexplained)
      policy.py                  # user-uploadable YAML policy schema + diff logic
      engine.py                  # combines findings -> category scores -> overall score
    reports/
      technical.py                # structured technical report (JSON/markdown)
      executive.py                 # plain-language summary (rule-based first;
                                    # LLM-assisted version is a stretch goal, must
                                    # have a non-LLM fallback that always works)
    utils/
      pcap_io.py                   # shared pcap reading helpers
  testbed/
    docker-compose.yml             # strongSwan peer containers
    configs/                       # one ipsec.conf per config combination,
                                    # named per the convention below
    scripts/
      generate_traffic.py          # drives curl/ffmpeg/scapy/smtp per traffic type
      capture.sh                    # tcpdump wrapper, writes labeled pcap
  data/
    pcaps/                          # raw captures (gitignored — see below)
    datasets/                       # extracted feature CSVs used for ML training
  tests/
  requirements.txt
  CLAUDE.md
```

## Data model (core objects)

- **Session** — one VPN connection instance: `id`, `pcap_path`, `mode`
  (tunnel/transport), `ip_version`, `created_at`, `ike_version`.
- **IkeFinding** — parsed from the handshake: `encryption_alg`, `auth_alg`,
  `dh_group`, `pfs_enabled`, `sa_lifetime`, `implementation_guess` (optional,
  from vendor ID strings).
- **FlowFinding** — per ESP flow: `predicted_traffic_type`, `confidence`,
  `packet_count`, `avg_packet_size`, `duration_s`.
- **ScoreResult** — `crypto_strength`, `compliance`, `key_management`,
  `metadata_exposure` (each 0–100), `overall_score`, `threat_matrix` (list of
  `{finding, likelihood, impact, recommendation}`).

Keep these as both SQLAlchemy models and pydantic schemas — pydantic ones are
what the API returns, so the frontend team gets stable contracts even if storage
changes later.

## API contract (frontend will consume this — keep it stable)

```
POST   /sessions/upload            multipart pcap upload -> Session
GET    /sessions                   list sessions
GET    /sessions/{id}               session detail
GET    /sessions/{id}/ike           IkeFinding
GET    /sessions/{id}/flows         list of FlowFinding
GET    /sessions/{id}/score         ScoreResult
GET    /sessions/{id}/report?type=executive|technical
POST   /policy                     upload a custom compliance policy YAML
GET    /policy/{id}
```

Every endpoint returns JSON. Report generation should also be retrievable as
plain markdown (`?format=markdown`) so the frontend or a doc-export step can turn
it into PDF/Word later without backend changes.

## Naming convention for testbed captures

`{mode}_{cipher}_{dh}_{pfs}_{iptype}_{traffic}_{timestamp}.pcap`
e.g. `tunnel_aesgcm256_dh19_pfson_ipv4_voip_20260901T1400.pcap`

This filename **is** the ground-truth label — the dataset builder parses it
directly. Do not deviate from this format or the ML pipeline's labeling breaks.

## Build order

1. **M0** — repo scaffold, FastAPI skeleton, health check endpoint, SQLite wired up.
2. **M1** — testbed: docker-compose with 2+ strongSwan peers, 4–6 config
   variants working, traffic generator producing at least ICMP/web/VoIP.
3. **M2** — IKE parser: tshark wrapper extracting cipher/DH/PFS/auth from a
   captured handshake, tested against every testbed config.
4. **M3** — flow feature extractor + dataset builder from labeled pcaps.
5. **M4** — train baseline traffic-type classifier (RandomForest first — get a
   working, explainable baseline before trying anything fancier), expose via
   `ml/classifier.py`.
6. **M5** — scoring engine against the rule tables, produces category scores +
   threat matrix.
7. **M6** — wire all of the above behind the API, generate technical report.
8. **M7** — executive report (rule-based fallback + optional LLM polish), tests,
   error handling for malformed/partial pcaps.

Do not start M4 before M2/M3 produce real labeled data — a classifier trained on
placeholder data will need retraining anyway and wastes the time slot.

## Commands

```
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

uvicorn app.main:app --reload          # run API (http://localhost:8000/docs for OpenAPI UI)
pytest                                  # run tests
docker compose -f testbed/docker-compose.yml up   # bring up VPN testbed
python testbed/scripts/generate_traffic.py --config tunnel_aesgcm256_dh19_pfson
python -m app.ml.train                  # retrain classifier from data/datasets/
```

## Non-goals for this phase

- No production/live network capture — lab testbed traffic only.
- No decryption of any kind, at any layer.
- No frontend code or styling decisions here.
- No blockchain component — despite the SIH theme tag, this PS itself does not
  require it; don't add one speculatively.

## Notes for whoever (or whatever) is coding this

- Prefer explainable models (RandomForest/XGBoost with feature importances) over
  black-box ones — the PS explicitly asks for an "AI Confidence Score," and you
  need to be able to justify it in front of judges.
- Every score the engine produces must trace back to a specific rule or model
  output — no unexplained numbers anywhere in the pipeline.
- Keep a small checked-in "golden" pcap set + pretrained model artifact so the
  demo works even if live capture fails on stage.
