# Demonstration Video Script

Per `PLAN.md` M9: script it around a deliberately weak config so the tool
visibly catches something real, plus one strong config for contrast. Target
run time: 4-6 minutes. Every step below maps to a specific, already-built
API endpoint or dashboard section — nothing here requires anything not already
in the repo.

**Before recording:** run the testbed (`backend/testbed/README.md`) across
at least these two configs, each with at least one traffic type captured,
and train the classifier (`python -m app.ml.dataset && python -m app.ml.train`)
so `/flows` and the Observer Profile section show real predictions instead of
`"unknown"`. If the testbed isn't ready yet, fall back to the same flow
using the hand-built demo pcaps from `backend/tests/fixtures/` — say so on
screen rather than presenting a synthetic pcap as a real capture.

---

## Scene 1 — The pitch (30s, talking head or title card)

> "IPsec VPN traffic is encrypted — but the handshake that sets it up isn't.
> This tool reads that cleartext handshake to identify exactly how a VPN is
> configured, uses machine learning to show what an observer could still
> infer from the encrypted traffic itself, and turns both into a security
> score a judge — or a security team — can act on."

State the core distinction on screen: **parsing** (cleartext IKE fields) vs
**ML** (encrypted ESP traffic-type inference). This is the differentiator;
lead with it.

## Scene 2 — The weak config (90s)

1. Show `backend/testbed/configs/tunnel_3des_dh1_pfsoff_ipv4.conf` on
   screen for 3 seconds — 3DES, MODP-768, PFS off. Say: "this is a
   deliberately weak, realistic-looking VPN config."
2. In the dashboard (`npm run dev` in `frontend/`), upload the pcap
   captured against that config.
3. **IKE Handshake table:** point at Encryption = 3DES-CBC, DH Group =
   MODP-768, PFS = Off. Say: "all of this came directly out of the
   handshake — no guessing."
4. **Security Score card:** point at a low `crypto_strength` and
   `key_management`, and the Threat Matrix table listing the specific
   findings (weak cipher, broken DH group, no PFS) with recommendations.
   Say: "every one of these numbers traces back to a named rule — nothing
   here is an unexplained score."

## Scene 3 — The strong config, and the twist (90s)

1. Upload a pcap captured against
   `tunnel_aesgcm256_dh19_pfson_ipv4.conf` (AES-GCM-256, ECP-256, PFS on)
   carrying VoIP-shaped traffic.
2. **Security Score card:** point at a high `overall_score` (A+ on crypto,
   compliance, key management).
3. **Immediately pivot to `metadata_exposure`** on the same screen: point
   out it's low (bad) because the flow was classified as VoIP at high
   confidence.
4. **Observer Profile card:** show the `traffic_identifiability` finding in
   plain language: "this flow was identified as VoIP at N% confidence,
   from packet size and timing alone — no decryption involved."
5. Say the line this whole feature exists for: **"Compliant does not mean
   private."** A tunnel can be cryptographically excellent and still leak
   what kind of traffic it's carrying, and this is the only part of the
   platform built specifically to prove that.

## Scene 4 — Traffic Classification / ESP flow list (45s)

1. Show the "Passive Heuristic Identifier (ESP)" card's per-flow list and
   confidence badges across a few different traffic types (web/voip/video/icmp
   if available).
2. Say: "the classifier never sees payload content — only packet size,
   timing, and burst pattern. Here's its feature-importance breakdown,"
   (point at whichever feature ranks highest in the trained model's
   `feature_importances_`, e.g. `avg_packet_size` or `burstiness`) "so this
   confidence score is explainable, not a black box."

## Scene 5 — Reports + close (60s)

1. Assessment Report card: switch between Technical and Executive, show
   the markdown download.
2. Read one sentence of the executive summary aloud — it should already
   name the risk band and top recommendation in plain language.
3. Closing line: "Everything you just saw — the parsing, the classifier,
   the scoring, the metadata-exposure finding — is one pcap upload and a
   few API calls. [`API-SPEC.md`] has the full contract if you want to
   build against it directly."

---

## Honesty notes to say on camera if asked (don't wait to be asked if time allows)

- If the `messaging` traffic type appears anywhere on screen: **state
  plainly it's an approximation of WhatsApp-style traffic characteristics,
  not a real captured WhatsApp session** — see `docs/dataset_card.md`.
- If using the synthetic demo pcaps rather than real testbed captures
  because the testbed wasn't run before recording: **say so on screen**,
  don't let it pass as a real capture.
- If asked the classifier's real accuracy: give the actual number from
  `python -m app.ml.train`'s output after running the testbed, not a
  number from this script or from the synthetic test fixture.
