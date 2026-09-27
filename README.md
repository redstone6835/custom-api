# Custom-API — a self-hosted LLM relay "customs house"

A model-relay gateway that performs **bidirectional auditing**, **independent
metering** and **automatic channel selection**. It sits between a user-facing
gateway (new-api) and upstream access points, and treats the relay as a border
that traffic must clear rather than as a dumb pipe.

```
user client (OpenAI / Anthropic compatible)
        |  user credential = a new-api token
        v
   new-api        (reused: tokens / users / quota / channels / logging)
        |  request and response bodies passed through verbatim
        v
   customsd   <-- this project: the customs proxy (single insertion point)
        |  A outbound: input audit, abuse detection, tool interception, redaction
        |  B inbound : usage verification, model fingerprint, injection and
        |              credential-leak detection, tool-call withholding
        |  C metering: local token recount, pricing, tamper-evident audit ledger
        v
   upstream access points A / B / C (official APIs, resellers, free tiers)
        ^
        |  prices, benchmark scores, fingerprint baselines, value ranking
   benchd  (intelligence layer)
```

The design rationale is written up in Chinese in [`README-zh.md`](README-zh.md);
this file is the operational summary.

---

## Why it exists

The project's premise is that **very few users and very few access points are
trustworthy**; everything else is untrusted by default. Two symmetric defences
follow, plus three guarantees that are never relaxed:

| Direction | Threat | Countermeasure |
|---|---|---|
| outbound (user → upstream) | abusive input gets the **upstream account banned**; resource abuse; dangerous tool calls | content rules, abuse detection, tool allowlist, argument path checks, redacted evidence |
| inbound (upstream → user) | **inflated usage claims**, substituted or degraded models, prompt injection, forged tool calls that steal keys | independent usage recount, behavioural fingerprint, injection rules, secret filtering, tool-call withholding |
| intelligence (side channel) | choosing an expensive *and* bad channel | price normalisation, promotion modelling, a layered benchmark suite, fingerprint baselines → value score → routing weight |

**Non-negotiable:** *metering, quota deduction and audit persistence are never
skipped, for any subject, under any trust level.* The trusted allowlist relaxes
**content inspection only** — the books are always kept. This is enforced by
`TestBlockedRequestStillConsumesQuota` and acceptance check 6.3.

---

## Deliverables

| Binary | Role |
|---|---|
| `customsd` | the customs proxy: outbound audit, inbound verification, metering, audit ledger, routing |
| `benchd` | intelligence daemon: price collection, fingerprint probes, benchmark runs, value scoring |
| `customsctl` | operator CLI: config validation, ledger verification and browsing, quota issuance, price comparison |

**Zero third-party dependencies** — the Go standard library only. That is what
makes a single static FreeBSD binary possible, with no ports, no CGO and no
module proxy needed at deploy time.

---

## Quick start

```sh
# 1. host-side tests (any platform with Go)
./deploy/scripts/deploy.sh local-test

# 2. create the libvirt-managed, headless FreeBSD test VM
./vm/create-vm.sh
./vm/create-vm.sh baseline      # install curl/jq/go/python3 inside the guest
virsh -c qemu:///system console customapi-freebsd

# 3. build, ship, install, verify
./deploy/scripts/deploy.sh all
```

`deploy.sh all` cross-compiles for `freebsd/amd64`, stages a release with
checksums, copies it, runs the installer (rc.d scripts, service user,
directories, config templates), ships the built web console, and then runs the
70-check end-to-end acceptance test against the real binary on FreeBSD.

Afterwards, on the target:

```sh
vi /usr/local/etc/customapi/customsd.env         # replace every CHANGE-ME token
chown root:customapi /usr/local/etc/customapi/customsd.env
chmod 640 /usr/local/etc/customapi/customsd.env
/usr/local/bin/customsctl config check -config /usr/local/etc/customapi/customs.json
service customsd start
service benchd start

# one command to confirm this deployment is actually usable
sh /usr/local/share/customapi/verify-deployment.sh
```

See [`docs/DEPLOYMENT-zh.md`](docs/DEPLOYMENT-zh.md) for the full guide,
including the pre-production checklist. (The deployment documentation is in
Chinese, matching the project's working language.)

---

## Interfaces

The gateway speaks three upstream protocols, so a client uses whichever one it
already has rather than adapting to a particular vendor:

| Client protocol | Endpoint |
|---|---|
| OpenAI Chat Completions | `POST /v1/chat/completions` |
| OpenAI Responses | `POST /v1/responses` (parsed natively, not aliased) |
| Anthropic Messages | `POST /v1/messages` |

**Any client protocol reaches any upstream.** A `supports` entry is served
verbatim on that surface; a protocol the provider did not declare is reached by
conversion, in both directions, for all six pairings of chat / responses /
anthropic. A converted exchange carries `X-Customs-Translated` on the response
and `translated` plus `upstream_protocol` in the audit record.

**Several providers means failover.** `routing.retry_on` includes `quota`, so a
provider whose own account cannot pay (an aggregator's 403
`insufficient_user_quota`) is skipped and the next provider answers. A bare 403 -
a banned key, a model without permission - stays terminal, because retrying it
everywhere multiplies failures and burns money.

```sh
# normal call — the gateway picks the channel
curl http://127.0.0.1:8080/v1/chat/completions \
  -H "Authorization: Bearer $CUSTOMS_USER_TOKEN" \
  -d '{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}'

# the same model through the Responses and Anthropic protocols
curl http://127.0.0.1:8080/v1/responses -H "Authorization: Bearer $CUSTOMS_USER_TOKEN" \
  -d '{"model":"gpt-4o","input":"hi"}'
curl http://127.0.0.1:8080/v1/messages -H "x-api-key: $CUSTOMS_USER_TOKEN" \
  -H "anthropic-version: 2023-06-01" \
  -d '{"model":"gpt-4o","max_tokens":256,"messages":[{"role":"user","content":"hi"}]}'

# what models exist, and which channels can serve each one
curl "http://127.0.0.1:8080/v1/models?detail=true" -H "Authorization: Bearer $CUSTOMS_USER_TOKEN"

# pin a channel you personally trust
curl ... -H "X-Customs-Channel: official" ...

# your own quota and usage
curl http://127.0.0.1:8080/v1/customs/usage -H "Authorization: Bearer $CUSTOMS_USER_TOKEN"

# price comparison for a concrete token mix
curl "http://127.0.0.1:8080/v1/customs/prices?model=gpt-4o&input_tokens=100000&output_tokens=20000"
```

A management console ships with the gateway and is served from the admin
listener — nine pages covering overview, providers, models, routing, usage,
audit, users, scores and settings:

```
http://127.0.0.1:8081/
```

The management surface is deliberately hard to reach: it binds to loopback, and
the handler refuses non-loopback callers even when the listener is moved. Remote
access requires `server.admin_remote: true` plus a `server.admin_token`, after
which every `/admin/*` call must present that token. The console's static shell
stays reachable so that the page which asks for the token can load at all; the
data behind it does not. `/admin/stats`, `/admin/config`, `/admin/users`,
`/admin/providers`, `/admin/models`, `/admin/audit`, `/admin/audit/verify`,
`/admin/usage`, `/admin/prices`, `/admin/prices/compare`, `/admin/scores`,
`/admin/fingerprints` are the endpoints the console drives.

---

## Highlights

### Usage verification, and an honest error budget

The gateway **never trusts the upstream's usage block**. It recounts tokens
independently and compares. The estimator is deliberately vocabulary-free (the
price of zero dependencies), calibrated against tiktoken o200k/cl100k and the
Anthropic tokenizer. Measured error: +7…17% on English prose, +15% on Chinese,
0% on JSON, −29% on code, −46% on digit-dense strings.

A deviation is therefore reported only when it exceeds **both** a relative
tolerance (0.25) and an absolute floor (8 tokens). The floor is not decorative:
on a five-token reply a three-token difference is +60%, so a purely relative
rule flags honest upstreams on exactly the short requests that health checks and
benchmark probes make. Measured on FreeBSD, omitting the floor drove an honest
channel's integrity score from 1.00 to **0.58** across a 36-case bench run;
with the floor it is 1.00 and 0/36 flagged, while genuine 20× inflation is still
caught.

### Tamper-evident audit ledger

One JSON object per line with a SHA-256 hash chain (`seq`, `prev_hash`,
`entry_hash`). Modifying, reordering, inserting or deleting any record breaks
verification from that point. A full rewrite is exposed by anchors periodically
pinned to a **separate file**. The gateway also:

- **verifies the whole chain at startup** and refuses to run against a broken
  ledger, rather than appending to it and laundering the tampering;
- **detects the ledger being replaced underneath it** (dev/ino comparison) and
  re-anchors onto the new file instead of writing into an orphaned inode.

### Streaming

"Forward early" and "withhold on violation" genuinely conflict. The gateway
chooses per channel trust: `buffered` (accumulate → audit → replay, zero leak)
for untrusted channels under `enforce`, `live` (forward, inspect a sliding
window, abort on a critical hit) for trusted channels. A pattern split across
several SSE deltas is still caught, because the detector keeps an overlap
window.

### Routing

```
value = capability × fingerprint_match × reliability × usage_integrity² / effective unit price
```

Priced with **this request's** real token mix, so a volume promotion the request
triggers takes effect immediately. Integrity is squared, so a channel caught
inflating is penalised harder than its linear share. Every decision records a
`route_reason`.

---

## Layout

```
custom-api/
├── src/customapi/            Go module (stdlib only)
│   ├── cmd/{customsd,benchd,customsctl}/
│   └── internal/
│       ├── protocol/   L0  wire types, SSE, in-place rewriting
│       ├── policy/     L2  rule engine + streaming sliding-window detector
│       ├── metering/   C   token estimator, usage comparison
│       ├── meter/          price normalisation, promotions, quoting
│       ├── route/          channel selection, health breaker, integrity decay
│       ├── audit/          hash-chained ledger, anchors, verification
│       ├── store/          quota, period reset, aggregate views
│       ├── discovery/      model catalogue merged from upstreams + config
│       ├── intel/      L3  JS divergence, benchmark suite, price collection
│       └── gateway/        HTTP pipeline, streaming, admin API
├── src/customapi/web/        management console (Vue 3 + Vite + TS, no CDN)
├── deploy/{rc.d,etc,scripts}/
├── lab/                      libvirt test VM driver on laboratory.lan
├── vm/                       libvirt test VM definition and creator
├── docs/
└── dist/                     release output + SHA256SUMS
```

---

## Tests

| Layer | What | Where |
|---|---|---|
| unit | rule engine, tokenizer calibration, price normalisation, routing, hash chain, SSE, config | `internal/*/*_test.go` |
| integration | the whole gateway pipeline against mock upstreams | `internal/gateway/gateway_test.go` |
| acceptance | 89 checks, on **real FreeBSD**, against the real binary | `deploy/scripts/smoke-test.sh` |
| intelligence | 13 checks: prices, fingerprint, bench, scorecard | `deploy/scripts/intel-test.sh` |
| console | credential handling, run in Node against the real module | `web/scripts/check-auth.mjs` |

The acceptance suite covers, besides proxying and metering: usage inflation,
prompt injection, malicious tool calls, abusive input, quota enforcement and
refusal auditing, ledger tamper detection, streaming, secret leakage, provider
key expansion and per-key failover, model discovery, all three protocols, and
the management API's reachability policy.

```sh
./deploy/scripts/deploy.sh local-test
./deploy/scripts/deploy.sh all
ssh customapi-bsd 'sudo sh /usr/local/share/customapi/intel-test.sh'
cd src/customapi/web && npm run test
```

---

## Status

- Host: `gofmt` clean, `go vet` clean, `go test -race` green
- FreeBSD acceptance: **89/89**, intelligence loop **13/13**
- FreeBSD intelligence pipeline: **13/13**
- Both services supervised by `daemon(8)`, running as the unprivileged
  `customapi` user, with pid file, log file and restart-on-crash

---

Deploying onto an existing libvirt host is documented in
[`docs/LAB-DEPLOYMENT-zh.md`](docs/LAB-DEPLOYMENT-zh.md).

---

## A note on what is *not* in this repository

No real credentials are published here. Specifically:

- **No provider API keys.** `deploy/etc/customs.json` names each key's
  environment variable (for example
  `CUSTOMS_PROVIDER_NAAPI_CC_KEY_MAIN_APIKEY`) and never a key value. Every
  token field in the example config is a `CHANGE-ME-*` placeholder.
- **No ledger, no audit data, no runtime state.** `var/`, logs and
  `__pycache__/` are ignored.
- **No build output or VM images.** `dist/` and the multi-hundred-megabyte
  `vm/*.qcow2*` are ignored; `make release` regenerates the former and
  `vm/create-vm.sh` re-downloads and checksum-verifies the latter.

What *is* published is disposable lab material, because the lab scripts are
meant to be reproducible as-is:

- the `lab/` and `vm/` provisioning scripts contain the **console root password
  of the throwaway test VM** (`customapi`, changeable with `--root-password`)
  and a **dedicated lab SSH public key** (comment `lab-vm-access`, unrelated to
  any personal key, and installed only inside the ephemeral guest);
- internal addressing (`10.10.1.0/24`, `laboratory.lan`) appears in the lab and
  deployment docs.

Both are local to a test environment that is rebuilt from scratch, and the VM
deployed in this lab has password authentication disabled (`PermitRootLogin
prohibit-password`, key-only). If you fork this and keep the `lab/` directory,
treat that password and key as disposable and regenerate them.
