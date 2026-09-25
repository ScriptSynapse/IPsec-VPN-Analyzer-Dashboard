# IPsec VPN Analyzer — Explained From Zero

A plain-language walkthrough of the problem statement, the crypto background
needed to follow it, and what this project actually implements. Written for
teammates who didn't build the backend and need to understand it well enough
to explain it to others (and for turning into a PPT).

## 1. What problem are we actually solving?

Companies, governments, and militaries use **VPNs** (Virtual Private Networks)
to send data securely over the internet. Most enterprise/government VPNs use
a protocol called **IPsec**.

The problem: IPsec can be configured in *dozens* of different ways — some
secure, some dangerously weak — and figuring out which one a given VPN is
using normally requires an expert staring at raw packet captures in
Wireshark for hours. NTRO wants a tool that:

1. Watches IPsec traffic (captured or live).
2. **Automatically figures out** what configuration it's using (encryption,
   key exchange, etc.).
3. **Grades** how secure that configuration is.
4. Guesses **what kind of traffic** is flowing inside it (without ever
   decrypting it — that's illegal/impossible and against the point).
5. Spits out a report a non-expert can read.

That's it. Everything below is just "how do you do steps 2–4."

## 2. Crypto basics you need (just enough, no more)

**IPsec has two phases:**

- **IKE (Internet Key Exchange)** — the "handshake." Two computers
  negotiate: which cipher will we use, which key-exchange method, how will
  we authenticate each other. **This handshake happens in cleartext** — it
  has to, because the two sides haven't agreed on a shared secret yet. This
  is the single most important fact in the whole project: *you don't need AI
  to read the handshake, you just need to parse it, because it's plaintext.*
- **ESP (Encapsulating Security Payload)** — the actual data, now encrypted
  using whatever was agreed in the handshake. This is truly opaque — you
  cannot read a single byte of the payload without the key.

**Key terms, plainly:**

| Term | Plain meaning |
|---|---|
| Encryption algorithm (AES-GCM, AES-CBC, 3DES...) | The lock. Some locks (AES-GCM 256-bit) are modern and strong; some (3DES) are from the 1990s and considered broken/weak today. |
| DH Group (Diffie-Hellman group) | The method two strangers use to agree on a secret key over a public channel without ever sending the key itself. Bigger/modern groups (elliptic curve, "ECP") = harder to crack. Old small groups (MODP-768) = crackable with enough compute. |
| PFS (Perfect Forward Secrecy) | If PFS is ON, cracking today's key doesn't let you decrypt yesterday's traffic — each session gets a fresh, disposable key. If OFF, one leaked key can unlock everything ever recorded. |
| Tunnel vs Transport mode | Tunnel mode wraps the *entire* original packet (used between two networks/gateways — e.g., site-to-site VPN). Transport mode only encrypts the payload, keeping the original IP header exposed (used host-to-host). |
| AEAD ciphers (AES-GCM, ChaCha20-Poly1305) | Modern ciphers that do encryption AND integrity-checking in one operation. Older designs (AES-CBC) need a *separate* algorithm (like HMAC-SHA) bolted on for integrity. This matters for scoring — see the bug fix below. |
| Replay protection | Stops an attacker from recording an encrypted packet and resending it later to trick the system. |
| SA (Security Association) | The "agreement record" both sides keep — which algorithm, which keys, how long the keys are valid (**lifetime**) before they must be renegotiated. |

That's genuinely all the crypto knowledge needed to follow the rest.

## 3. The one idea the whole project hinges on

> **Don't use AI where deterministic parsing works. Only use AI where
> nothing else is possible.**

This project has exactly **two kinds of "intelligence,"** and they must
never be confused:

1. **Deterministic parsing (no ML at all).** Cipher, DH group, PFS, auth
   method, IKE version — all sitting in cleartext in the IKE handshake. We
   just read the packet fields with `tshark` (Wireshark's own packet
   dissector, run as a subprocess) and pull the values out. If we trained a
   machine-learning model to "predict" the cipher, that would be fake AI —
   the answer is already written in the packet.

2. **Machine learning (real AI, and it's the only place we need it).** The
   traffic *inside* ESP is encrypted — genuinely unreadable. But we can
   still guess "is this VoIP, web browsing, video, email, or a messaging
   app?" by looking at the **shape** of the encrypted traffic from the
   outside: packet sizes, timing between packets, burst patterns, flow
   duration. A video stream looks different from a voice call looks
   different from ICMP pings, purely from these metadata patterns — nobody
   needs to decrypt anything to see that.

This distinction is exactly what the problem statement's part (c) is asking
for ("AI-Based Protocol Identification... Predict Type of traffic inside
ESP") and it's the part judges will scrutinize hardest, because it's easy to
fake.

## 4. What we actually built, mapped to the problem statement

### (a) VPN Testbed Generation ✅
Two Docker containers running real **strongSwan** (an open-source IPsec
implementation), configured to negotiate real VPN tunnels. We built config
files (`ipsec.conf`) for combinations of:
- Tunnel mode / (mostly Tunnel — Transport partially covered)
- AES-128, AES-256, AES-GCM, 3DES, AES-CBC+SHA1
- Multiple DH groups (MODP-768/1024/2048/14, and ECP-256/384 elliptic curve)
- PFS on/off
- IPv4 (IPv6 not yet exercised)

We hit a real snag: the stock Ubuntu strongSwan package was missing the
plugins for AES-GCM and elliptic-curve DH. We rebuilt strongSwan from source
with the full plugin set to fix that — now the modern AEAD/ECP configs
actually negotiate, not just the older ones.

### (b) Traffic Capture ✅
`tcpdump`, driven by a script (`capture.sh`), captures the full exchange —
IKE negotiation + ESP data packets — into labeled `.pcap` files. A traffic
generator script (`generate_traffic.py`) drives six traffic types across the
tunnel: ICMP (ping), web (HTTP), VoIP-shaped UDP, video-shaped UDP,
email-shaped UDP, and messaging-shaped UDP (WhatsApp-like bursts — see
honesty note below).

### (c) AI-Based Protocol Identification — split as explained above
- **IPsec protocol / IKE version / mode / encryption / auth / DH group / SA
  characteristics** → deterministic parser (`app/ike/parser.py`), verified
  byte-for-byte against Wireshark's own decode on real captures. We actually
  found and fixed **4 real bugs** in this parser (wrong algorithm ID tables,
  wrong metadata source, duplicate proposals) by testing against genuine
  handshakes instead of just made-up test data — that's a real engineering
  result worth mentioning to teammates/judges.
- **Traffic type prediction inside ESP** → a Random Forest classifier
  trained on flow-level features (packet size stats, inter-arrival timing,
  burstiness, throughput) extracted purely from ESP headers/metadata — never
  payload. This is the genuine ML component.

### (d) Security Assessment ✅
A rules engine (`app/scoring/rules.py` + `engine.py`) that scores:
- Cryptographic strength (cipher + key length)
- Configuration compliance against a policy (with a default policy aligned
  to NIST SP 800-77 / RFC 8221, and support for uploading a **custom**
  policy YAML)
- DH group / key exchange strength
- PFS on/off
- SA lifetime
- (Replay protection and some metadata-exposure checks — implemented at a
  basic level)

Every number the engine produces traces back to a named rule — no "mystery
score." We also caught and fixed a real bug here: modern AEAD ciphers
(AES-GCM) don't have a *separate* integrity algorithm by design (encryption
+ integrity are combined in one operation) — the engine used to wrongly
penalize that as "missing integrity," dragging a legitimately strong
config's score down to 64/100. Fixed, it now correctly scores ~84/100.

### (e) Output ✅
- **Technical report** (structured, detailed) and **Executive report**
  (plain-language summary, rule-based, works even without any LLM) — both
  retrievable as JSON or Markdown.
- **Risk/overall score**, **Threat Matrix** (finding → likelihood → impact →
  recommendation), and an **AI Confidence Score** attached to every
  traffic-type prediction (so we're not hiding the ML's uncertainty).

### Deliverables checklist
- ✅ Working prototype (FastAPI backend + React dashboard)
- ✅ AI classification engine (Random Forest, explainable via feature
  importances — deliberately chosen over a black-box model so we can
  justify the confidence score to judges)
- ✅ Interactive dashboard (upload, session list/detail, tunnels, policies,
  reports — plus the newer Agents/Topology monitoring view)
- ✅ Security assessment report
- ⚠️ Demonstration video — not yet made
- ⚠️ Technical documentation — partially written (`docs/`), needs polishing
- ✅ Dataset used for training — real, but small (see honesty section)

## 5. The newest addition: "live-ish" monitoring (Wazuh-style)

Instead of doing live capture on a judge's laptop, we built something closer
to how Wazuh (a well-known security monitoring tool) runs its endpoint
agents. A lightweight **agent** script runs on an authorized machine (e.g.,
a teammate's PC), continuously captures traffic in the background, and
periodically uploads it to the central dashboard.

- Each agent registers once and gets a secret API key (shown only once,
  like a GitHub token).
- A **"Global Topology"** page shows every agent, every tunnel it's fed data
  into, and every peer IP seen — as a live-updating graph, so you can
  visually show "here are N devices/agents reporting in, here's who they're
  talking to."
- **"Tunnels (Observer Profiles)"** — a "tunnel" here just means one logical
  VPN connection being watched over time (it can span multiple pcap
  uploads/sessions as the same conversation continues); "Observer Profile"
  is just our label for the aggregated view of that one tunnel's
  characteristics across everything captured about it, as opposed to
  looking at a single one-off pcap in isolation.

## 6. Be honest with your teammates/judges about these things

- The **real training dataset is currently small**: 40 flow rows from 30
  real pcaps, across 5 of the 17 planned configs. It proves the *entire
  pipeline* works end-to-end on real, non-synthetic data — capture → parse
  → extract features → train → classify. It does **not** yet prove the
  classifier generalizes broadly; that needs more captures across more
  configs, which is straightforward additional work, not a redesign.
- `messaging` (WhatsApp-like) traffic is **approximated** — shaped synthetic
  UDP traffic matching WhatsApp's known public characteristics, not an
  actual captured WhatsApp session (no internet egress in the lab). Say
  this plainly if asked.
- IPv6 and Transport mode are implemented in the config matrix but less
  exercised in the dataset than IPv4/Tunnel mode.
- No decryption happens anywhere, at any layer — by design, and that's
  actually a selling point, not a limitation: it proves the traffic-type
  inference is legitimately side-channel-based.

---

Next step: turn this into a PPT structure (title → problem → approach →
architecture diagram → live demo screenshots → results/honesty slide →
future work).
