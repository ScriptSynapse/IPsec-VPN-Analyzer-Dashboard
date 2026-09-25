# IPsec VPN Analyzer — Full Implementation Plan
**Target PS:** AI-Powered IPsec VPN Protocol Analyzer and Security Assessment Framework (NTRO — Blockchain & Cybersecurity theme, cybersecurity half only)
**Current repo state:** M0 complete (FastAPI skeleton + SQLite health check). Everything below is what turns that skeleton into the full PS deliverable.
> Citation note: this plan references RFC 8221 and NIST SP 800-77 for cryptographic scoring baselines. I don't have live document access — verify exact section numbers/recommendations against the actual RFC/NIST text before citing them to judges.
---
## 0. Ground Rules (carried over from CLAUDE.md — do not violate these)
1. **Two different kinds of "detection." Don't blur them.**
   - IKE Phase 1/2 fields (cipher, DH group, PFS flag, auth method, IKE version) are **cleartext** in the handshake → this is **parsing**, not ML. Extract with tshark. Training a model to predict a field that's already sitting in plaintext is fake AI and will get torn apart by judges who know IPsec.
   - Only the **traffic type inside encrypted ESP packets** (VoIP / web / video / email / ICMP) is genuinely hidden → this is where real ML happens, using side-channel flow features (size, timing, burst pattern).
2. **Never attempt to decrypt ESP.** All ESP-layer inference is from observable metadata only. This is a security assessment tool, not a decryption tool — breaking this breaks the entire premise.
3. Every score the engine outputs must trace back to a named rule or a model's feature importance. No unexplained numbers.
4. Keep a checked-in "golden" pcap set + pretrained model so the live demo doesn't die if capture fails on stage.
---
## 1. Target Architecture
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
                                          classifier (RandomForest/XGBoost)
              │                                    │
              └────────────────┬───────────────────┘
                                ▼
                       Scoring Engine (rules.py)
                       → category scores + overall score + threat matrix
                                │
                                ▼
                   Reports (Executive + Technical, JSON/MD)
                                │
                                ▼
                    FastAPI REST API  ──────►  Dashboard (React or Streamlit)
```
---
## 2. Final Repo Structure
```
backend/
  app/
    main.py
    core/          [DONE] config.py, db.py, schemas.py
    api/
      routes_capture.py       # upload pcap, list/get sessions
      routes_analysis.py      # trigger analysis, get IKE/flow findings
      routes_scoring.py       # get score, upload custom policy
      routes_reports.py       # get executive/technical report
    ike/
      parser.py               # tshark subprocess wrapper
      schemas.py               # IkeHandshake, SaProposal pydantic models
    flow/
      extractor.py             # per-ESP-flow feature extraction (Scapy)
      features.py               # feature name constants / column schema
    ml/
      dataset.py                # build labeled dataset from data/datasets/
      train.py                  # training script -> ml/artifacts/
      classifier.py              # load model, predict + confidence
      artifacts/                 # baseline_v1.joblib (checked in for demo safety)
    scoring/
      rules.py                   # crypto/DH/PFS/lifetime weight tables
      policy.py                   # YAML policy schema + diff logic
      engine.py                   # findings -> scores -> threat matrix
    reports/
      technical.py
      executive.py
    utils/
      pcap_io.py
  testbed/
    docker-compose.yml
    configs/                      # one ipsec.conf pair per config combo
    scripts/
      generate_traffic.py
      capture.sh
  data/
    pcaps/
    datasets/
  tests/
frontend/
  (dashboard — see Section 9)
docs/
  technical_documentation.md
  dataset_card.md
```
---
## 3. Milestones
### M1 — VPN Testbed (PS section a)
**Goal:** Docker-based lab that stands up IPsec tunnels across a representative config matrix and generates labeled traffic through them.
**Stack:** strongSwan (two containers, `left` and `right`), Docker Compose, a router/NAT container if you want tunnel-mode realism across a "public" segment.
**Config matrix** — don't attempt the full combinatorial explosion (mode × cipher × DH × PFS × IP version = 100+ combos). Build a **representative matrix** of ~16 canonical VPN configs, then run every traffic type through each:
| # | Mode | Cipher | DH Group | PFS | IP Version |
|---|------|--------|----------|-----|------------|
| 1 | Tunnel | AES-128-CBC + HMAC-SHA256 | Group 14 (2048-bit MODP) | On | IPv4 |
| 2 | Tunnel | AES-256-CBC + HMAC-SHA256 | Group 14 | On | IPv4 |
| 3 | Tunnel | AES-128-GCM | Group 19 (256-bit ECP) | On | IPv4 |
| 4 | Tunnel | AES-256-GCM | Group 19 | On | IPv4 |
| 5 | Tunnel | AES-256-GCM | Group 14 | **Off** | IPv4 |
| 6 | Tunnel | AES-128-CBC + HMAC-SHA1 | Group 2 (1024-bit, weak) | Off | IPv4 |
| 7 | Transport | AES-128-CBC + HMAC-SHA256 | Group 14 | On | IPv4 |
| 8 | Transport | AES-256-GCM | Group 19 | On | IPv4 |
| 9 | Tunnel | AES-256-GCM | Group 19 | On | IPv6 |
| 10 | Tunnel | AES-128-CBC + HMAC-SHA256 | Group 14 | On | IPv6 |
| 11 | Tunnel | AES-256-CBC + HMAC-SHA256 | Group 21 (521-bit ECP) | On | IPv4 |
| 12 | Tunnel | 3DES + HMAC-SHA1 | Group 1 (768-bit, broken) | Off | IPv4 |
| 13–16 | IKEv1 vs IKEv2 variants of a couple of the above, to test IKE-version parsing | | | | |
Rows 6 and 12 are **intentionally weak configs** — you need at least a few "bad" configs in the dataset so the scoring engine has something to flag, and so you can demo the tool catching a genuinely insecure deployment (this matters a lot for the judge demo).
**Traffic types per config** (per PS: VoIP, web-browsing, e-mail, ICMP, video streaming; WhatsApp is a special case — see note below):
- **ICMP** — trivial: `ping` across the tunnel.
- **Web-browsing** — `curl`/`wget` loop against a local nginx serving mixed page sizes, or `ab`/`siege` for repeated HTTP(S) requests.
- **E-mail** — local Postfix/MailHog container + `swaks` or Python `smtplib` sending messages of varying size/attachments.
- **VoIP** — `iperf3` in UDP mode with VoIP-like bitrate/packet-size (~20ms packetization, ~80-byte payloads) is a legitimate proxy, or use `sipp` if you want actual SIP/RTP signaling.
- **Video streaming** — `ffmpeg` streaming a file over RTP/UDP or an local HTTP video server pulled via `ffmpeg`/`curl` range requests.
- **WhatsApp** — you cannot capture real WhatsApp traffic in an isolated lab (no internet egress, no real client pairing). **Document this limitation explicitly** rather than faking it: either (a) omit it and state why, or (b) approximate it as "messaging app" traffic using a generator tuned to WhatsApp's known public traffic characteristics (small bursty packets, TLS 1.3, keepalives) and clearly label it as an *approximation* in the dataset card. Judges will respect an honest limitation far more than a silently fabricated label.
**Naming convention (already specified in CLAUDE.md — keep it, the dataset builder depends on it):**
```
{mode}_{cipher}_{dh}_{pfs}_{iptype}_{traffic}_{timestamp}.pcap
e.g. tunnel_aesgcm256_dh19_pfson_ipv4_voip_20260901T1400.pcap
```
**Files to build:**
- `testbed/docker-compose.yml` — strongSwan left/right + nginx + mailhog + a client/traffic-gen container.
- `testbed/configs/*.conf` — one `ipsec.conf` + `ipsec.secrets` pair per matrix row.
- `testbed/scripts/generate_traffic.py` — CLI: `--config <name> --traffic <type> --duration <s>`, drives the right tool per traffic type.
- `testbed/scripts/capture.sh` — wraps `tcpdump -i <iface> -w <labeled_filename>.pcap`, started before traffic gen, stopped after.
**Definition of done:** running `docker compose up`, then looping `generate_traffic.py` across the 16 configs × 6 traffic types, produces ~96 correctly-named labeled pcaps in `data/pcaps/`, each containing IKE negotiation + ESP + the target traffic.
---
### M2 — IKE Parser (PS section c, deterministic half)
**Goal:** From a pcap's IKE handshake, extract every cleartext SA/config field.
**Approach:** subprocess into `tshark -r <pcap> -Y "isakmp" -T json`, parse the JSON tree for both IKEv1 (`isakmp.sa.attr`) and IKEv2 (`isakmp.notify`, `isakmp.enc`, `isakmp.tsi/tsr` for tunnel vs transport, `isakmp.sa.enc/prf/integ/dh`) payloads. tshark's dissectors already decode ISAKMP/IKE — don't hand-roll this.
**Fields to extract →`IkeFinding`:**
- `ike_version` (v1 vs v2 — from the ISAKMP header's exchange type / version field)
- `mode` (tunnel vs transport — from traffic selectors in IKEv2, or SA payload's encapsulation mode attribute in IKEv1)
- `encryption_alg` (e.g., AES-CBC-128, AES-GCM-256)
- `auth_alg` / integrity algorithm (SHA1, SHA256, or "none" if using an AEAD cipher like GCM that folds in integrity)
- `dh_group` (numeric group ID → human name, e.g., 14 → "2048-bit MODP")
- `pfs_enabled` (Phase 2 / Child SA proposal includes a DH group → PFS on; absent → PFS off)
- `sa_lifetime` (from Notify payloads or vendor-specific lifetime attributes; strongSwan/vendor defaults may need fallback logic if not explicitly negotiated)
- `auth_method` (PSK vs certificate/RSA-sig vs EAP)
- `implementation_guess` (optional — from Vendor ID payload strings, e.g., strongSwan's VID)
**Files:**
- `app/ike/parser.py` — `parse_ike(pcap_path: Path) -> IkeHandshake`
- `app/ike/schemas.py` — `IkeHandshake`, `SaProposal` pydantic models
**Definition of done:** run against all 16 testbed configs — parser output matches the known ground truth (the config that generated the pcap) for every field, 100% of the time. This is a parsing correctness bar, not an ML accuracy bar — it should be exact.
**Test:** `tests/test_ike_parser.py` — parametrized over all 16 golden pcaps, asserts each field against the known config.
---
### M3 — Flow Feature Extractor (PS section c, ML half — input prep)
**Goal:** From ESP packets in a pcap, extract per-flow statistical features (never touching payload content).
**Approach:** Scapy to iterate ESP packets, group by flow 5-tuple (src/dst IP, SPI in place of ports since ESP has no ports), compute:
- `packet_count`, `total_bytes`, `duration_s`
- packet size: `mean`, `std`, `min`, `max`, plus a small histogram (e.g., 5 bins)
- inter-arrival time: `mean`, `std`, `median`
- `bytes_per_second`, `packets_per_second`
- directionality: ratio of client→server vs server→client bytes (VoIP/video are more symmetric or server-heavy; web is bursty client-request/server-response)
- burstiness: coefficient of variation of inter-arrival times, or count of "burst events" (packets within X ms of each other)
- ESP sequence number gaps (useful later for replay-protection assessment too, not just classification)
**Files:**
- `app/flow/extractor.py` — `extract_flows(pcap_path: Path) -> list[FlowRecord]`
- `app/flow/features.py` — the canonical ordered feature-name list (single source of truth so training and inference never drift out of sync)
**Definition of done:** running the extractor against a labeled pcap produces one row per ESP flow with all features populated and the traffic-type label attached (parsed from filename).
---
### M4 — ML Traffic-Type Classifier (PS section c, ML half — model)
**Goal:** Train a model that predicts traffic type (VoIP/web/email/ICMP/video/[messaging]) from flow features alone, with a confidence score.
**Do not start this before M1–M3 produce real labeled data.** A model trained on placeholder data needs retraining anyway.
- `app/ml/dataset.py` — walks `data/pcaps/`, runs the M3 extractor on each, parses the filename for the ground-truth traffic-type label, writes a combined CSV to `data/datasets/`.
- `app/ml/train.py` — train/test split (stratified by traffic type, hold out entire pcaps not just rows, to avoid leakage from the same flow). Start with **RandomForestClassifier** as the explainable baseline (CLAUDE.md is right about this — you need to justify the "AI Confidence Score" to judges, so a model with `feature_importances_` you can show on a slide beats an unexplainable one). Try XGBoost as a second model and keep whichever generalizes better on held-out pcaps.
- Report: accuracy, per-class precision/recall/F1, confusion matrix — save these as an artifact for the technical report/demo.
- `app/ml/classifier.py` — loads the saved `.joblib` model, exposes `predict(features) -> (traffic_type, confidence)`, where confidence = the model's predicted-class probability (`predict_proba`).
**Definition of done:** classifier hits a reasonable accuracy on held-out pcaps (document whatever you actually get — don't pre-commit to a number you haven't measured), and every prediction returns a confidence score, not just a label.
**Checked-in fallback:** commit one trained `.joblib` baseline to `ml/artifacts/` (per CLAUDE.md's non-goal about demo reliability) so the demo works even if retraining fails live.
---
### M5 — Scoring Engine (PS section d)
**Goal:** Turn `IkeFinding` + `FlowFinding` into category scores, an overall score, and a threat matrix — every number traceable to a named rule.
**Rule categories and example weight logic** (baseline off RFC 8221's guidance on ESP/AH algorithm requirements and NIST SP 800-77's IPsec VPN guidance — verify exact wording before citing to judges):
1. **Cryptographic strength** (0–100)
   - AES-256-GCM → 100 (AEAD, no downgrade risk)
   - AES-128-GCM → 90
   - AES-256-CBC+HMAC-SHA256 → 75 (secure but MAC-then-encrypt overhead vs AEAD)
   - AES-128-CBC+HMAC-SHA256 → 65
   - AES-*-CBC+HMAC-SHA1 → 40 (SHA1 deprecated for new deployments)
   - 3DES / DES / NULL cipher → 0–10 (critical fail, flag explicitly)
2. **Key exchange / DH group strength**
   - Group 19/20/21 (ECP curves) → 100
   - Group 14 (2048-bit MODP) → 80 (acceptable minimum per current guidance)
   - Group 2/5 (1024-bit or less) → 20, flagged as "below modern minimum"
   - Group 1 (768-bit) → 0, critical fail
3. **PFS enabled/disabled** — binary modifier: PFS off multiplies the key-exchange sub-score down (e.g., ×0.5) and adds a specific threat-matrix entry, since a single compromised long-term key would expose all past traffic without PFS.
4. **IKE version** — IKEv2 → full score; IKEv1 → penalty + flag ("IKEv1 is legacy; consider migration") since IKEv1 has known implementation-flaw history and weaker built-in DoS protection.
5. **Auth method** — certificate-based → full score; PSK → penalty scaled by an estimate of PSK strength if available, flagged as weaker operationally (PSK distribution/rotation risk) even when cryptographically fine.
6. **Key/SA lifetime** — flag lifetimes that are excessively long (e.g., Phase 1 > 24h, Phase 2/Child SA > 8h are common upper bounds in hardening guides) since long lifetimes increase the value of a single compromised key.
7. **Replay protection** — check for anti-replay window presence/size in the SA; flag if disabled or window is unusually large.
8. **Metadata exposure** — even with strong encryption, ESP headers leak SPI, sequence numbers, and packet-size/timing patterns (this ties directly into the ML classifier's own success — if the classifier can reliably guess traffic type from metadata, that itself is evidence of a metadata-exposure finding worth reporting).
**Overall score:** weighted combination of the category scores (define explicit weights, e.g., crypto 30%, key exchange 25%, PFS 15%, lifetime 10%, replay 10%, metadata 10% — tune these, just don't leave them unexplained).
**Threat matrix:** list of `{finding, likelihood, impact, recommendation}` — one row per triggered rule (e.g., "3DES in use → likelihood: high [known weak], impact: high [confidentiality], recommendation: migrate to AES-256-GCM").
**Custom policy support:** `app/scoring/policy.py` — let a user upload a YAML policy overriding what counts as acceptable (e.g., an org that mandates FIPS-only algorithms), diff findings against it, surface policy-specific compliance failures separate from the general security score.
**Files:**
- `app/scoring/rules.py` — the weight tables, one constant/dict per category, comments citing the source guidance.
- `app/scoring/policy.py`
- `app/scoring/engine.py` — `score(ike: IkeFinding, flows: list[FlowFinding]) -> ScoreResult`
---
### M6 — API Layer (wires M1–M5 together)
Already scaffolded in CLAUDE.md's contract — implement the actual route bodies:
```
POST   /sessions/upload            multipart pcap upload -> Session
GET    /sessions                   list sessions
GET    /sessions/{id}              session detail
GET    /sessions/{id}/ike          IkeFinding
GET    /sessions/{id}/flows        list of FlowFinding (+ predicted traffic type + confidence)
GET    /sessions/{id}/score        ScoreResult (+ threat matrix)
GET    /sessions/{id}/report?type=executive|technical&format=json|markdown
POST   /policy                     upload custom compliance policy YAML
GET    /policy/{id}
```
Each upload should kick off the M2→M3→M4→M5 pipeline (synchronously is fine for a hackathon demo scale; note in the technical doc that a production version would queue this async).
**Files:** `app/api/routes_capture.py`, `routes_analysis.py`, `routes_scoring.py`, `routes_reports.py`, registered in `main.py`.
---
### M7 — Reports (PS section e)
- `app/reports/technical.py` — full structured dump: every IKE field, every flow's features + predicted type + confidence, the full score breakdown, the full threat matrix. JSON by default, Markdown on request (so it can be piped into a PDF/Word export step later without backend changes).
- `app/reports/executive.py` — plain-language summary for a non-technical reader: overall score, top 3 risks, top 3 recommendations, one paragraph. **Rule-based template first** (must always work). An LLM-polished version (e.g., feeding the technical findings to an LLM API to generate prose) is a legitimate stretch goal — but keep the non-LLM fallback as the default path, since a live demo can't depend on an external API call succeeding.
**Also produce, as standalone PS deliverables (not backend code, but explicit line items):**
- **AI Confidence Score** — surface the classifier's `predict_proba` output prominently in both reports, not buried in raw JSON.
- **Risk Score** — the overall score from M5, clearly labeled and explained (what it means, how it was computed).
- **Threat Matrix** — rendered as an actual table in both the markdown report and the dashboard, not just a JSON blob.
---
### M8 — Dashboard (PS explicit deliverable: "Interactive dashboard")
CLAUDE.md defers this as "a separate phase" — that's fine for backend sequencing, but it's a **required deliverable**, so plan it explicitly and don't let it slip to the last two days.
**Two viable paths — pick based on your timeline, not both:**
- **Fast path (recommended if time is tight): Streamlit.** A single Python app hitting your own FastAPI endpoints (or importing the pipeline functions directly). You can have session upload, IKE findings table, flow/traffic-type breakdown chart, score gauges, and threat-matrix table working in a day or two. Judges care more about seeing the analysis than about frontend polish.
- **Polished path: React (or Next.js) + a charting lib (Recharts).** Pages: Upload → Session list → Session detail (tabs for IKE / Flows / Score / Threat Matrix / Reports). Only worth it if you have frontend bandwidth beyond the ML/scoring work — don't let dashboard polish eat time from M4/M5, which are the parts that actually prove the "AI" and "security assessment" claims in the PS title.
**Minimum dashboard views regardless of path:**
1. Upload/session list
2. IKE handshake summary (mode, cipher, DH, PFS, IKE version, auth method) — this is your "protocol identification" proof
3. Traffic-type breakdown per flow with confidence scores — this is your "AI" proof
4. Score breakdown (radar/bar chart of the categories) + overall score
5. Threat matrix table
6. Executive report view + download (PDF/Word/Markdown)
---
### M9 — Packaging the Non-Code Deliverables
The PS lists these explicitly — treat them as first-class tasks, not afterthoughts:
- **Demonstration video** — script it around a *deliberately weak config* (row 6 or 12 from the M1 matrix) so the tool visibly catches something real, plus one strong config for contrast. Show upload → parsing → classification → score → threat matrix → report, in under the time limit judges expect.
- **Technical documentation** — expand `CLAUDE.md`'s content into a judge-facing `docs/technical_documentation.md`: architecture diagram, the parsing-vs-ML distinction (this is your strongest differentiator — lead with it), scoring rule tables with citations, model training methodology, and known limitations (WhatsApp approximation, synchronous pipeline, lab-only testbed).
- **Dataset used for training/testing** — package `data/datasets/*.csv` (the flow-feature dataset, not raw pcaps if size is an issue) with a `docs/dataset_card.md` describing: config matrix, traffic types (and the WhatsApp caveat), feature schema, class balance, train/test split methodology.
---
## 4. Suggested Build Order & Sequencing
Do not reorder M4 ahead of M1–M3 — there's no data to train on otherwise. Suggested parallelization if you have more than one person:
- **Person A:** M1 (testbed) → M2 (IKE parser) — these unblock everything else and are pure infrastructure/parsing, no ML dependency.
- **Person B:** M5 (scoring rules) can be drafted against the data model in parallel, even before real findings exist, then wired up once M2 lands.
- **Person C:** M8 (dashboard) can build against mocked API responses matching the M6 contract, then swap in the real API once M6 lands.
- Once M1–M3 produce a real dataset → M4 (ML) becomes the critical path; don't split focus away from it once it starts, since it's the PS's core "AI-Based" claim.
- M6 → M7 → M9 close out the loop.
---
## 5. Deliverables Checklist (map directly to the PS's "Expected Solution/Deliverables")
- [ ] Working software prototype — M1–M8 integrated end-to-end
- [ ] AI classification engine — M4
- [ ] Interactive dashboard — M8
- [ ] Security assessment report — M7
- [ ] Demonstration video — M9
- [ ] Technical documentation — M9
- [ ] Dataset used for training/testing — M1 + M3 + M9
---
## 6. Honesty Notes for the Judge Q&A
Have straight answers ready for these, because judges who know IPsec will ask:
1. *"Why isn't the crypto algorithm itself ML-predicted?"* → Because it's cleartext in the handshake; predicting it with ML would be strictly worse than parsing it, and pretending otherwise is exactly the kind of "fake AI" this PS is designed to filter out.
2. *"How do you classify traffic without decrypting it?"* → Side-channel flow features only (size/timing/burst) — same family of technique used in encrypted-traffic classification research generally, not a novel decryption method.
3. *"What's your model's actual accuracy, and on what test set?"* → Have the real confusion matrix from M4 ready, not a claimed number.
4. *"Is WhatsApp traffic really WhatsApp?"* → No — be upfront that it's an approximation given lab constraints, and explain why (no real-world egress/pairing in an isolated testbed).
---
## Note on repo state vs. this plan (added when this plan was received)

This plan was written as if starting from M0. In reality, by the time it arrived, M0–M7 (per `CLAUDE.md`) and Phase 2/M8 Observer Profile (per `PHASE2.md`) were already built, tested, and pushed — see `IMPLEMENTED.md` and `IMPLEMENTED-PHASE2.md`. The mapping:

| This plan's milestone | Status |
|---|---|
| M1 testbed (original 6-config version) | Done, unverified (no Docker in the build sandbox) — see `backend/testbed/` |
| M1 testbed expanded to 17-config matrix + messaging traffic type | **Done** — see `backend/testbed/README.md`, still unverified against live Docker |
| M2 IKE parser | Done, verified against real tshark output |
| M3 flow feature extractor | Done, verified |
| M4 ML classifier | Done, verified (pipeline mechanics; no real trained baseline yet — no real captures exist). Train/test split was fixed to group by source pcap (`GroupShuffleSplit`) rather than by row, per this plan's own leakage warning. |
| M5 scoring engine | Done, verified — cited to RFC 8221 / NIST SP 800-77 already; category breakdown differs slightly from this plan's (crypto_strength/compliance/key_management/metadata_exposure vs. this plan's 6-way split) — not restructured, see `docs/technical_documentation.md` §6 for the mapping and why replay-protection scoring was deliberately not added (no reliable observable signal) |
| M6 API layer | Done, verified, plus Phase 2 additions (`observer-profile`, tunnel correlation) beyond this plan's contract |
| M7 reports | Done, verified |
| M8 dashboard | **Done** — originally built as a Streamlit app, since replaced at the user's request with a Vite + React + Tailwind dashboard (`frontend/`, see `docs/technical_documentation.md` §9), verified end-to-end against a live backend with headless Playwright (upload -> analyze -> every page renders real data, no exceptions) |
| M9 docs/demo packaging | **Done** — `docs/technical_documentation.md`, `docs/dataset_card.md`, `docs/demo_script.md` |
