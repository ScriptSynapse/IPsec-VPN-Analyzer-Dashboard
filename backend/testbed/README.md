# IPsec testbed

Two strongSwan gateways (`alice`, `bob`) connect two simulated LANs
(`alice-host`, `bob-host`) over IPsec. Traffic sent between the two host
containers gets ESP-encapsulated by the gateways, giving you real,
config-labeled captures for the IKE parser and ML pipeline.

**Update — actually run against real Docker (2026-09-02):** this environment
turned out to have a working `dockerd` after all. Findings from actually
running it, not guessing:

- `docker compose up -d --build` genuinely builds and starts all four
  containers (`alice`, `bob`, `alice-host`, `bob-host`) with no changes
  needed to this compose file or Dockerfile.
- Real IKE_SA negotiation works for every MODP-based config in the matrix
  (verified: `tunnel_3des_dh1_pfsoff_ipv4`, `tunnel_aes128_dh14_pfson_ipv4`,
  `tunnel_aes128_dh14_pfson_ipv4_ikev1`, `tunnel_aes256_dh14_pfson_ipv4`,
  `tunnel_aes128sha1_dh2_pfsoff_ipv4`) -- `ipsec statusall` on `alice` shows
  a genuine `ESTABLISHED` SA with the exact negotiated proposal from the
  applied `.conf`, exchanged with the independent `bob` container over the
  real `public` bridge network.
- **The AES-GCM and ECP-DH configs (dh19/dh20/dh21, all `*aesgcm*` rows)
  fail to even start IKE negotiation** on this image: `charon`'s loaded
  plugin list has no `gcm` or `ecp`/`openssl` plugin (Ubuntu 24.04's
  `strongswan`/`libcharon-extra-plugins` packages don't ship one under any
  discoverable package name -- confirmed via `apt-cache search` and by
  grepping the image for the plugin `.so` files, both empty). Getting those
  6 rows working needs a strongSwan build with `--enable-openssl` (or
  `--enable-gcm --enable-ecp`), which likely means building from source
  instead of the `apt` packages this Dockerfile currently uses. Not fixed
  here since it doesn't change the conclusion below.
- **CHILD_SA (the actual ESP tunnel) never installs, on any config,
  including the ones whose IKE_SA does establish.** strongSwan reports
  `unable to install inbound and outbound IPsec SA (SAD) in kernel`. This
  is not a strongSwan or config problem: running `ip xfrm state add ...
  proto esp ...` directly inside the container (bypassing strongSwan
  entirely) fails with `Error: Requested type not found` -- the same for
  `proto ah`. This sandbox's kernel does not implement the XFRM ESP/AH
  transform at all, so no ESP packet can ever be produced here, by
  anything, regardless of config.
- **Even the IKE control-plane packets that do successfully negotiate
  cannot be captured to a pcap.** `tcpdump -i eth0` (and `-i any`) inside
  `alice`, run with *no* BPF filter at all, captures 0 packets while an
  `ipsec up` in the same window provably succeeds (the SA comes up). There
  is also no packet-capture tooling on the host outside the containers to
  fall back to. This points to raw-socket/`AF_PACKET` capture being blocked
  by this specific sandbox (consistent with a gVisor/Firecracker-style
  container sandbox, which is what `uname -a` on this host reports), not a
  tcpdump or filter mistake.

Net effect: this specific cloud sandbox can run Docker and can genuinely
negotiate real strongSwan IKE_SAs, but it is structurally unable to produce
a single real `.pcap` file -- neither the ESP data path nor packet capture
itself works here, for reasons independent of this repo's code. Someone
running this same `docker-compose.yml` on unrestricted Docker (a real VM,
a normal CI runner, a laptop) should not hit either of these two problems;
they are properties of this sandbox, not of the testbed definition.

**Update — run on real (unrestricted) hardware (2026-09-02):** confirmed.
On a real machine, the CHILD_SA installs for real (`ipsec statusall` shows
`INSTALLED` with real ESP SPIs) and `tcpdump` captures real traffic, once
two real bugs were fixed:
- `capture.sh` hardcoded `eth0` as the public interface, but Docker doesn't
  guarantee that ordering across a container's networks -- fixed to
  resolve the interface by IP instead (see the script).
- `generate_traffic.py`'s cleanup `pkill -f` was matching its own invoking
  command's argv and killing itself before its `|| true` fallback ran --
  fixed by obfuscating the search pattern.

**The GCM/ECP plugin gap above is now fixed too.** `backend/testbed/Dockerfile`
now builds strongSwan from source (`./configure --enable-openssl`, using
the full default plugin set rather than a hand-picked minimal one -- an
earlier attempt at a minimal `--disable-defaults` build hit a recursive-make
ordering bug in this exact configure combination and was abandoned in favor
of the standard, well-tested default-plugins-plus-openssl path). Verified
for real: `tunnel_aesgcm256_dh19_pfson_ipv4` now negotiates
`AES_GCM_16_256/PRF_HMAC_SHA2_256/ECP_256` and installs a real CHILD_SA,
confirmed via both `ipsec statusall` and a real captured pcap parsed
correctly by `app/ike/parser.py`. All 17 configs in the matrix are now
expected to negotiate; only the 5 MODP-based ones plus one AES-GCM/ECP one
have been individually spot-checked so far.

## Usage

```bash
cd backend/testbed

# 1. Pick a config variant (see configs/*.conf) and activate it.
./scripts/apply_config.sh tunnel_aesgcm256_dh19_pfson_ipv4

# 2. Bring the stack up.
docker compose up -d --build

# 3. Wait for the tunnel to establish, then check status.
docker exec alice ipsec status

# 4. Generate labeled traffic and capture it concurrently.
python scripts/generate_traffic.py --traffic voip --duration 20 &
./scripts/capture.sh tunnel_aesgcm256_dh19_pfson_ipv4 voip 25
wait

# 5. Repeat step 4 for each traffic type (icmp, web, voip, video, email,
#    messaging), and repeat steps 1-4 for each config variant in
#    configs/*.conf, to build a dataset that spans every combination.

# 6. Switching config variants requires restarting the daemons:
./scripts/apply_config.sh tunnel_aes256_dh14_pfson_ipv4
docker compose restart alice bob
```

Captures land in `backend/data/pcaps/`, named per the convention in
`CLAUDE.md`: `{mode}_{cipher}_{dh}_{pfs}_{iptype}_{traffic}_{timestamp}.pcap`.
That filename is the ground-truth label the dataset builder
(`app/ml/dataset.py`) parses -- don't rename captures by hand.

## Config variants

A representative matrix (per `PLAN.md` section 1) rather than the full
mode × cipher × DH × PFS × IP-version combinatorial explosion. Rows marked
**weak** are deliberately insecure -- keep them, the scoring engine and the
demo both need at least one genuinely bad config to catch.

| File | Mode | Cipher | DH group | PFS | IKE | Notes |
|---|---|---|---|---|---|---|
| `tunnel_aes128_dh14_pfson_ipv4.conf` | tunnel | AES-128-CBC/SHA-256 | MODP-2048 | on | v2 | common minimum-acceptable baseline |
| `tunnel_aes256_dh14_pfson_ipv4.conf` | tunnel | AES-256-CBC/SHA-256 | MODP-2048 | on | v2 | common enterprise baseline |
| `tunnel_aesgcm128_dh19_pfson_ipv4.conf` | tunnel | AES-GCM-128 | ECP-256 | on | v2 | AEAD baseline |
| `tunnel_aesgcm256_dh19_pfson_ipv4.conf` | tunnel | AES-GCM-256 | ECP-256 | on | v2 | strong AEAD baseline |
| `tunnel_aesgcm256_dh14_pfsoff_ipv4.conf` | tunnel | AES-GCM-256 | MODP-2048 | **off** | v2 | isolates the PFS penalty from cipher/DH |
| `tunnel_aes128sha1_dh2_pfsoff_ipv4.conf` | tunnel | AES-128-CBC/SHA-1 | MODP-1024 | **off** | v2 | **weak** -- SHA-1 deprecated, DH below minimum |
| `transport_aes128_dh14_pfson_ipv4.conf` | transport | AES-128-CBC/SHA-256 | MODP-2048 | on | v2 | gateway-to-gateway only |
| `transport_aesgcm256_dh19_pfson_ipv4.conf` | transport | AES-GCM-256 | ECP-256 | on | v2 | gateway-to-gateway only |
| `tunnel_aesgcm256_dh19_pfson_ipv6.conf` | tunnel | AES-GCM-256 | ECP-256 | on | v2 | IPv6 -- needs an IPv6-enabled compose network, see the file's header comment |
| `tunnel_aesgcm256_dh20_pfson_ipv6.conf` | tunnel | AES-GCM-256 | ECP-384 | on | v2 | IPv6, same caveat as above |
| `tunnel_aes128_dh14_pfson_ipv6.conf` | tunnel | AES-128-CBC/SHA-256 | MODP-2048 | on | v2 | IPv6, same caveat as above |
| `tunnel_aes256_dh21_pfson_ipv4.conf` | tunnel | AES-256-CBC/SHA-256 | ECP-521 | on | v2 | strongest EC group in the matrix |
| `tunnel_aes256_dh5_pfsoff_ipv4.conf` | tunnel | AES-256-CBC/SHA-256 | MODP-1536 | **off** | v2 | isolates the PFS penalty from cipher/DH |
| `tunnel_3des_dh1_pfsoff_ipv4.conf` | tunnel | 3DES/SHA-1 | MODP-768 | **off** | v1 | **critically weak** -- broken DH group, deprecated cipher |
| `tunnel_3des_dh2_pfsoff_ipv4.conf` | tunnel | 3DES/SHA-1 | MODP-1024 | **off** | v1 | **weak** |
| `tunnel_aes128_dh14_pfson_ipv4_ikev1.conf` | tunnel | AES-128-CBC/SHA-256 | MODP-2048 | on | v1 | IKEv1 sibling of the AES-128 row, for IKE-version parsing coverage |
| `tunnel_aes256_dh14_pfson_ipv4_ikev1.conf` | tunnel | AES-256-CBC/SHA-256 | MODP-2048 | on | v1 | IKEv1 sibling of the AES-256 row |

## Traffic types

`generate_traffic.py --traffic <type>` supports `icmp`, `web`, `voip`,
`video`, `email`, and `messaging`. The last one is an **explicit
approximation**: it is not possible to capture real WhatsApp (or similar)
traffic in an isolated lab testbed with no internet egress and no real
client pairing, so `messaging` instead generates small, bursty packets plus
a periodic keepalive tuned to WhatsApp's known public traffic
characteristics. This is documented, not silently faked -- never present
it as literal WhatsApp traffic to judges (see `docs/dataset_card.md`).

## Troubleshooting

- `docker exec alice ipsec statusall` shows SA state and negotiated algorithms.
- `docker exec alice journalctl -u strongswan` (or `/var/log/syslog` on
  Ubuntu) has charon's debug output if a tunnel won't come up --
  `charondebug` in each `.conf` is already turned up for this.
- If the tunnel establishes but LAN-to-LAN traffic doesn't flow, check that
  the `ip route replace` in each host container's entrypoint actually ran
  (`docker exec alice-host ip route`) and that `net.ipv4.ip_forward=1` took
  effect on both gateways.
