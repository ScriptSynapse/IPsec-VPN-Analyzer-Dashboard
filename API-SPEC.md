# API-SPEC.md

## IPsec VPN Analyzer — Backend API Specification

Base URL (local dev): `http://localhost:8000`
All responses are JSON unless `?format=markdown` is passed (returns `text/markdown`).
Interactive docs: `GET /docs` (Swagger UI), `GET /openapi.json`.

---

## Health

### `GET /health`

**Purpose:** Liveness/readiness probe — confirms the app is up and the database is reachable.

**Accepts:** nothing.

**Returns:** `200 OK`
```json
{
  "status": "ok" | "degraded",
  "app_name": "IPsec VPN Analyzer",
  "database_connected": true
}
```

---

## Sessions

A **Session** is one uploaded pcap capture — the root object everything else hangs off of.

### `POST /sessions/upload`

**Purpose:** Upload a pcap/pcapng capture and create a Session for it. First step of every workflow.

**Accepts:** `multipart/form-data`, field `file` (the pcap/pcapng file).

**Returns:** `201 Created`
```json
{
  "id": "uuid",
  "filename": "capture.pcap",
  "mode": null,
  "ip_version": null,
  "ike_version": null,
  "created_at": "2026-09-01T16:03:14.605192",
  "tunnel_id": null,
  "peer_label": null,
  "peer_src_ip": null,
  "peer_dst_ip": null
}
```
`mode`/`ip_version`/`ike_version`/`peer_src_ip`/`peer_dst_ip` are populated later by `/analyze`, not at upload time.

**Errors:** `400 Bad Request` if the uploaded file isn't a valid pcap/pcapng (checked by magic bytes).

---

### `GET /sessions`

**Purpose:** List all sessions, newest first.

**Accepts:** nothing.

**Returns:** `200 OK` — array of the same Session object shown above.

---

### `GET /sessions/{id}`

**Purpose:** Fetch one session's metadata.

**Accepts:** `id` (path, session UUID).

**Returns:** `200 OK` — Session object.

**Errors:** `404` if the session doesn't exist.

---

### `PATCH /sessions/{id}`

**Purpose:** Attach a session to a `tunnel_id` (and/or set a human-readable `peer_label`) so it can be correlated with other captures of the same monitored tunnel over time — required input for the multi-session Observer Profile findings.

**Accepts:** JSON body, both fields optional:
```json
{ "tunnel_id": "office-vpn", "peer_label": "HQ<->Branch" }
```
Fields omitted are left unchanged (not cleared).

**Returns:** `200 OK` — updated Session object.

**Errors:** `404` if the session doesn't exist.

---

### `POST /sessions/{id}/analyze`

**Purpose:** Runs the actual analysis pipeline against the uploaded pcap: parses the IKE handshake (tshark), extracts ESP flow features (Scapy), classifies each flow's traffic type (ML), and records the peer IP pair. Must be run once before any of `ike`/`flows`/`score`/`report`/`observer-profile` will return data.

**Accepts:** nothing (all input is the pcap already stored against this session).

**Returns:** `202 Accepted`
```json
{ "session_id": "uuid", "status": "analyzed", "flow_count": 1 }
```

**Errors:**
- `404` — session doesn't exist
- `422 Unprocessable Entity` — IKE parsing failed (no ISAKMP traffic found, or tshark error) or flow extraction failed

---

## IKE / Flow findings

### `GET /sessions/{id}/ike`

**Purpose:** Returns the IKE handshake fields extracted deterministically from cleartext packet data — cipher, DH group, PFS, auth method, IKE version. This is direct parsing, not inference.

**Accepts:** nothing.

**Returns:** `200 OK`
```json
{
  "session_id": "uuid",
  "ike_version": "2",
  "exchange_type": "34",
  "encryption_alg": "AES-GCM-16",
  "auth_alg": "HMAC-SHA2-256-128",
  "dh_group": "ECP-384",
  "pfs_enabled": true,
  "sa_lifetime": 3600,
  "implementation_guess": "strongSwan",
  "proposals": [
    { "encryption_alg": "AES-GCM-16", "key_length": 256, "auth_alg": null, "dh_group": "ECP-384", "lifetime_seconds": null }
  ],
  "vendor_ids": []
}
```

**Errors:** `404` — session doesn't exist, or `/analyze` hasn't been run yet.

---

### `GET /sessions/{id}/flows`

**Purpose:** Returns per-ESP-flow traffic-type classification and the observable metadata it was inferred from (size/timing) — never payload content.

**Accepts:** nothing.

**Returns:** `200 OK` — array:
```json
[
  {
    "flow_key": "10.0.0.1->10.0.0.2:spi=0xc0ffee00",
    "predicted_traffic_type": "voip",
    "confidence": 0.92,
    "packet_count": 40,
    "avg_packet_size": 160.0,
    "std_packet_size": 5.0,
    "duration_s": 0.78,
    "feature_importances": { "avg_packet_size": 0.31 }
  }
]
```
`predicted_traffic_type` is `"unknown"` with `confidence: 0.0` if no classifier model has been trained yet — this is the deliberate fail-closed fallback, not a bug.

**Errors:** `404` — session doesn't exist, or `/analyze` hasn't been run yet.

---

## Scoring

### `GET /sessions/{id}/score`

**Purpose:** Runs the rule-based security assessment against the parsed IKE handshake (and flow classifications) and returns category scores + a threat matrix. Recomputes and overwrites any previous score for this session on every call.

**Accepts:**
- `id` (path)
- `policy_id` (query, optional) — score against a previously-uploaded custom policy instead of the default one.

**Returns:** `200 OK`
```json
{
  "session_id": "uuid",
  "crypto_strength": 96.5,
  "compliance": 100.0,
  "key_management": 91.67,
  "metadata_exposure": 8.0,
  "overall_score": 96.35,
  "threat_matrix": [
    {
      "finding": "ESP flow metadata (packet size/timing) strongly reveals traffic type",
      "likelihood": "High",
      "impact": "Medium",
      "recommendation": "Consider padding or traffic-shaping to reduce side-channel fingerprinting."
    }
  ],
  "policy_id": null
}
```

**Important semantics:** `overall_score` is computed from `crypto_strength` + `compliance` + `key_management` **only**. `metadata_exposure` is reported independently and never blended in — a session can legitimately be A+ on `overall_score` and F on `metadata_exposure` at the same time (see the Observer Profile endpoints below for why).

**Errors:** `404` — session doesn't exist, `/analyze` hasn't been run yet, or `policy_id` was given but doesn't exist.

---

### `POST /policy`

**Purpose:** Upload a custom compliance policy (YAML) that overrides the default minimum-strength thresholds, banned algorithm lists, PFS requirement, max SA lifetime, and category weights used by `/score`.

**Accepts:** `multipart/form-data`, field `file` (a `.yaml` file). Recognized keys, all optional (defaults shown):
```yaml
min_encryption_score: 60
min_auth_score: 50
min_dh_score: 60
require_pfs: true
max_sa_lifetime_s: 86400
banned_encryption_algs: ["DES-CBC", "DES", "DES-IV64", "DES-IV32"]
banned_auth_algs: ["HMAC-MD5", "HMAC-MD5-128", "DES-MAC", "KPDK-MD5"]
category_weights: {crypto_strength: 0.45, compliance: 0.30, key_management: 0.25}
```
A `metadata_exposure` key in `category_weights` is accepted but silently ignored — it is never part of `overall_score`.

**Returns:** `201 Created`
```json
{ "id": "uuid", "name": "strict.yaml", "created_at": "2026-09-01T16:03:14.605192", "definition": { "min_encryption_score": 80 } }
```

**Errors:** `400 Bad Request` — invalid YAML or a value that fails schema validation.

---

### `GET /policy`

**Purpose:** List all uploaded policies, newest first.

**Accepts:** nothing.

**Returns:** `200 OK` — array of the same shape as the upload response.

---

### `GET /policy/{id}`

**Purpose:** Fetch a previously-uploaded policy (e.g. to pass its id to `/score?policy_id=`).

**Accepts:** `id` (path).

**Returns:** `200 OK` — same shape as the upload response.

**Errors:** `404` if it doesn't exist.

---

## Reports

### `GET /sessions/{id}/report`

**Purpose:** Generates a human-readable report bundling session + IKE + flow + score data. Two flavors: a detailed technical report for engineers, and a rule-based plain-language executive summary for non-technical readers (with an optional LLM-polish hook that always falls back to the rule-based text if unset/unavailable).

**Accepts:**
- `id` (path)
- `type` (query, `technical` default | `executive`)
- `format` (query, `json` default | `markdown`)

**Returns (`type=technical`, `format=json`):** `200 OK`
```json
{
  "session": { "id": "uuid", "filename": "capture.pcap" },
  "ike": {
    "ike_version": "2",
    "exchange_type": "34",
    "chosen_proposal": { "encryption_alg": "AES-GCM-16", "dh_group": "ECP-384" },
    "all_proposals": [],
    "pfs_enabled": true,
    "sa_lifetime": null,
    "implementation_guess": null,
    "vendor_ids": []
  },
  "flows": [ { "flow_key": "...", "predicted_traffic_type": "voip" } ],
  "score": { "overall_score": 96.35 }
}
```

**Returns (`type=executive`, `format=json`):** `200 OK`
```json
{
  "session_id": "uuid",
  "risk_band": "Low Risk",
  "overall_score": 96.35,
  "summary": "This VPN session (...) was assessed as **Low Risk**, with an overall security score of 96/100. ..."
}
```
`risk_band` is one of `"Low Risk"` / `"Moderate Risk"` / `"High Risk"` / `"Critical Risk"`.

`format=markdown` returns the same data rendered as a markdown document (`text/markdown`) instead of JSON — usable directly as a doc export.

**Errors:** `404` — session doesn't exist, or analysis (`/analyze`) and scoring (`/score`) haven't both run yet.

---

## Observer Profile (Phase 2)

The read layer that answers "what could a passive observer actually learn from this tunnel, regardless of how strong the crypto is." Built purely from data the pipeline above already computed — no new packet parsing, no new ML model.

Every finding (except `insufficient_history`) has this shape:
```json
{
  "category": "traffic_identifiability" | "padding_exposure" | "temporal_pattern" | "peer_stability" | "volume_signature",
  "description": "plain-language, judge-readable explanation",
  "confidence": 0.0,
  "evidence": { "...": "raw stats backing the claim" },
  "mitigation": "how to reduce this exposure (single-session findings only)"
}
```
Multi-session findings below the 2-session threshold instead emit exactly one:
```json
{ "category": "insufficient_history", "sessions_needed": 2, "sessions_have": 1 }
```

### `GET /sessions/{id}/observer-profile`

**Purpose:** Single-session exposure findings — `traffic_identifiability` (a flow was confidently fingerprinted as a specific traffic type from size/timing alone) and `padding_exposure` (packet-size variance heuristic for whether TFC padding looks like it's in effect) — plus multi-session correlation findings if this session has a `tunnel_id` shared with 2+ other sessions, or an explicit `insufficient_history` marker if not.

**Accepts:**
- `id` (path)
- `format` (query, `json` default | `markdown`)

**Returns:** `200 OK`
```json
{
  "session_id": "uuid",
  "tunnel_id": "office-vpn",
  "findings": [
    {
      "category": "traffic_identifiability",
      "description": "Flow 10.0.0.1->10.0.0.2:spi=0xc0ffee00 was identified as voip traffic at 92% confidence, from ESP packet size and timing alone -- no decryption was performed or is possible.",
      "confidence": 0.92,
      "evidence": { "flow_key": "10.0.0.1->10.0.0.2:spi=0xc0ffee00", "predicted_traffic_type": "voip", "packet_count": 40, "avg_packet_size": 160.0, "duration_s": 0.78 },
      "mitigation": "Pad or shape traffic, or multiplex several traffic types over the same tunnel, to reduce the classifier's ability to fingerprint this flow."
    },
    {
      "category": "padding_exposure",
      "description": "Flow ... shows low packet-size variance (coefficient of variation 0.00), consistent with TFC padding or otherwise normalized packet sizes. This is a heuristic inference from size variance, not direct confirmation that TFC padding was negotiated -- that flag isn't observable on the wire.",
      "confidence": 0.5,
      "evidence": { "flow_key": "...", "coefficient_of_variation": 0.0, "std_packet_size": 0.0, "avg_packet_size": 228.0 },
      "mitigation": "Enable ESP TFC padding, if your IPsec stack supports it, to mask true payload sizes."
    },
    { "category": "insufficient_history", "sessions_needed": 2, "sessions_have": 1 }
  ]
}
```

**Errors:** `404` if the session doesn't exist.

---

### `GET /tunnels/{tunnel_id}/observer-profile`

**Purpose:** Aggregated Observer Profile across every session sharing this `tunnel_id` — combines each session's single-session findings with the multi-session correlation findings (`temporal_pattern`: recurring time-of-day activity; `peer_stability`: whether the peer IP pair stayed constant; `volume_signature`: whether byte volume per classified traffic type is consistent across sessions).

**Accepts:**
- `tunnel_id` (path)
- `format` (query, `json` default | `markdown`)

**Returns:** `200 OK`
```json
{
  "tunnel_id": "office-vpn",
  "session_count": 2,
  "findings": [
    { "category": "padding_exposure", "description": "...", "confidence": 0.5, "evidence": {}, "mitigation": "..." },
    {
      "category": "temporal_pattern",
      "description": "Across 2 sessions, tunnel activity clusters around 16.1:00 UTC (std dev 0.0h) -- a recurring time-of-day pattern is observable, which narrows down when this tunnel is likely to be active without decrypting anything.",
      "confidence": 0.7,
      "evidence": { "session_start_hours_utc": [16.05, 16.07], "mean_hour": 16.06, "std_hour": 0.01 }
    },
    {
      "category": "peer_stability",
      "description": "The peer IP pair stayed constant across all 2 sessions, making this tunnel easy to re-identify as the same pair over time.",
      "confidence": 0.9,
      "evidence": { "distinct_peer_pairs": [["10.0.0.1", "10.0.0.2"]] }
    },
    {
      "category": "volume_signature",
      "description": "Byte volume per classified traffic type is consistent across sessions for: voip. A stable volume signature for a traffic type makes recurring sessions easier to correlate even without decrypting them.",
      "confidence": 0.6,
      "evidence": { "by_traffic_type": { "voip": { "mean_bytes": 6400.0, "coefficient_of_variation": 0.02, "consistent": true } } }
    }
  ]
}
```
Below the 2-session threshold, `findings` contains only the per-session single-session findings plus one `insufficient_history` object (temporal/peer/volume findings are never fabricated from a single session).

**Errors:** `404` if no sessions exist with this `tunnel_id`.

---

## Error response shape

All error responses (400/404/422) share FastAPI's default shape:
```json
{ "detail": "human-readable explanation of what went wrong and what to do next" }
```

## Stretch / not yet implemented

- `GET /tunnels/{tunnel_id}/drift` — cross-session IKE downgrade detection (cipher weakens, DH group drops, PFS toggles off, SA lifetime lengthens on rekey). Planned as Phase 2's M9, not started.
