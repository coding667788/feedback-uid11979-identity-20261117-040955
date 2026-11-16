# Strict local JWT verifier with multi-issuer JWKS isolation and key rotation

A from-scratch JWT verification service for Windows + Python 3.12 (CPU only).
Only `cryptography` is used, and only for RSA signing/verification primitives.
There is **no** use of a JWT/OIDC library, no Docker, and no external identity
platform. All keys and tokens are local test data.

Components:

| Component | Entry point |
|---|---|
| JWT verifier HTTP service | `python -m jwt_service.server_main --config config/local.json` |
| JWKS HTTP simulator (controllable/blockable) | `python -m jwt_service.simulator_main --config ... --keystore ...` |
| Standalone token generator | `python -m jwt_service.token_cli --keystore ... --issuer ...` |
| Test-key generator | `python -m jwt_service.tools_init --config ... --keystore ...` |
| Automated tests (153) | `python -m pytest tests -q` |
| End-to-end demo with real subprocesses | `python scripts/demo.py` |

---

## 1. Windows install and run

### 1.1 Create the environment

```bat
cd /d "<this folder>"
py -3.12 -m venv .venv
.venv\Scripts\python.exe -m pip install --upgrade pip
.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
```

`requirements*.txt` pin every dependency exactly. For an offline install the
wheels are already in `vendor/wheels/`:

```bat
.venv\Scripts\python.exe -m pip install --no-index --find-links vendor\wheels -r requirements-dev.txt
```

If the base interpreter has no bundled `pip` and no network, create the venv
first (a venv from `py -3.12` bundles pip) and then install from
`vendor\wheels` exactly as above; this is the path verified for the designated
runtime `D:/CC_Codex_FeedBack/runtimes/cc005-csv-python312/python.exe`.

The wheels are `cryptography-44.0.3-cp39-abi3-win_amd64`, `cffi-2.1.1`,
`pycparser-3.12`, `pytest-8.3.3`, `pluggy-1.5.0`, `iniconfig-2.0.0`,
`packaging-24.1`, `colorama-0.4.6`. All are pure/binary wheels for
CPython 3.12 on Windows x64; no compiler is required.

### 1.2 Generate test keys and start the pieces

Four terminals (or use `scripts\demo.py`, which does all of this in one go):

```bat
:: 0) create private test keys under state\ (git-ignored)
.venv\Scripts\python.exe -m jwt_service.tools_init --config config\local.json --keystore state\test-keys.json

:: 1) JWKS simulator on 127.0.0.1:9001
.venv\Scripts\python.exe -m jwt_service.simulator_main --config config\local.json --keystore state\test-keys.json --port 9001

:: 2) verification service on 127.0.0.1:8080
.venv\Scripts\python.exe -m jwt_service.server_main --config config\local.json

:: 3) mint a token and call the verifier
.venv\Scripts\python.exe -m jwt_service.token_cli --keystore state\test-keys.json --issuer https://issuer-a.test --sub alice --ttl 120
curl -s -X POST -H "Authorization: Bearer <token>" http://127.0.0.1:8080/verify
```

### 1.3 Run the tests

```bat
.venv\Scripts\python.exe -m pytest tests -q
.venv\Scripts\python.exe scripts\demo.py
```

No environment variable or global config is needed. The tests bind only
loopback ports and use an injected clock, so they are independent of the real
time of day.

---

## 2. Trust configuration

`config/local.json` is the only source of trust anchors:

```json
{
  "issuers": [
    {"issuer": "https://issuer-a.test",
     "jwks_url": "http://127.0.0.1:9001/issuer-a/jwks.json",
     "audience": "api-a"},
    {"issuer": "https://issuer-b.test",
     "jwks_url": "http://127.0.0.1:9001/issuer-b/jwks.json",
     "audience": "api-b"}
  ],
  "admin_token": "local-admin-token-change-me-0123456789",
  "listen_host": "127.0.0.1",
  "listen_port": 8080,
  "snapshot_ttl_seconds": 60,
  "auto_refresh_cooldown_seconds": 5,
  "fetch_timeout_seconds": 2.0,
  "limits": {"max_bytes": 262144, "max_keys": 32,
             "min_rsa_bits": 2048, "max_rsa_bits": 8192, "max_kid_length": 256}
}
```

Validation rules enforced at load time: unique issuer identifiers, unique JWKS
URLs, unique audiences, loopback listen host, `http`/`https` only, no
credentials/fragment in the URL, minimum admin token length, numeric ranges for
every limit, and rejection of unknown `limits` keys and duplicate JSON members.

---

## 3. Verification rules (task item 1)

Accepted token: compact JWS, **exactly three** segments, `alg` exactly `RS256`.
Every rule below has a dedicated test.

* **Signature** is verified with the RSA key resolved for the token's `iss`,
  never with anything referenced by the header.
* **Claims**: `iss`, `sub`, `aud`, `exp`, `nbf` are all required and validated.
  `iss` must exactly equal a configured issuer (also serves as the index into
  that issuer's cache, which is what keeps identical kids isolated). `sub` must
  be a non-empty string. `aud` is a string or non-empty string array and must
  contain that issuer's configured audience.
* **Time fields** must be JSON integers. Booleans (`true`/`false`) and floats
  (including `1.8e9`) are rejected with `json_member_not_integer`. `iat`, when
  present, is type-checked the same way.
* **Boundary**: `nbf <= now < exp` with no leeway. Exactly `now == nbf` is
  accepted, exactly `now == exp` is rejected (`token_expired`). The injected
  clock supplies one `now` used for the key-freshness check, `nbf` and `exp`.
* **Duplicate JSON members** anywhere in the header or payload are rejected by
  a custom parser (`strict_json`), including nested objects.
* **Non-canonical base64url** is rejected: padding, `+`/`/`, and pad bits that
  do not round-trip through re-encoding (e.g. `"QR"`) all fail. Decoded
  segments must be valid UTF-8 JSON objects.
* **`crit`** is always rejected (no JWS extensions are implemented); `b64:
  false` is rejected too.
* **Algorithm confusion**: `none`, `HS256`/HMAC-with-the-public-key, `RS512`
  and anything else are rejected by the `alg` gate before any key lookup.
  The classic HMAC confusion attack is a test case.
* **`jku` / `x5u` / `x5c` / `jwk`** in the header are ignored. A test asserts
  the simulator receives no request to the attacker-supplied URL and that the
  total request count is unchanged.
* **Key material**: only RSA public keys. `kty` must be `RSA`; `use`, if
  present, must be `sig`; `alg`, if present, must be `RS256`; `key_ops` must
  contain `verify` and must not contain `sign`; modulus must be at least 2048
  bits and at most the configured maximum; exponent must be odd, ≥3, <2^64.
  EC/oct keys, private members (`d`, `p`, `q`, ...), non-minimal integers
  (leading zero byte) and even moduli are rejected.
* **Identical kid across issuers** is isolated because there is one snapshot per
  issuer, keyed by the configured `iss`, and the verifier never mixes them.

Responses never echo the token, its header or key material.

---

## 4. Snapshot lifecycle (task item 2)

Each issuer owns one `IssuerKeyCache` with a single immutable snapshot object.

* **TTL 60 s.** A snapshot is fresh while `now < fetched_at + 60`. Exactly at
  `expires_at` it is stale.
* **Atomic publication.** A fetched body is parsed and validated in full
  (`parse_jwks_document`) *before* the snapshot reference is swapped under the
  issuer lock. `KeySnapshot.keys` is a read-only mapping, the dataclass is
  frozen, and the old object is never mutated. Any malformed document leaves the
  previous snapshot untouched; there is no partial update.
* **Whole-document rejection** on: invalid JSON, duplicate members, missing or
  non-array `keys`, zero keys, more than `max_keys` keys, more than `max_bytes`
  bytes, duplicate `kid`, non-string/oversized `kid`, any non-RSA key, private
  key material, bad base64url/minimality, exponent/modulus problems, or modulus
  outside `[min_rsa_bits, max_rsa_bits]`.
* **No verification-result cache.** `resolve` is called on every request. A
  token that verified before the swap is re-checked against the new snapshot;
  deleting an old kid gives `unknown_kid`, replacing a kid's key gives
  `signature_invalid` for the old token. Tests assert this for both HTTP and
  direct verification, and re-verify real signatures every time.
* **Failure behaviour.** If a refresh fails and the old snapshot is still
  fresh, it keeps serving. If it is expired, every request fails closed with
  HTTP 503 `keys_unavailable`. Lifetime is never extended: `expires_at` is
  fixed at fetch time and a failed attempt does not touch it. This is asserted
  both for a fast HTTP 500 and for a client-side fetch timeout.

---

## 5. Concurrency and refresh coordination (task item 3)

State per issuer: one in-flight operation (`_inflight`), a monotonically
increasing operation counter, the published snapshot's `seq`, and
`_next_auto_refresh_at`.

* **Single-flight.** Concurrent unknown-kid requests observe the same in-flight
  operation and wait on it. 128 distinct random kids produce exactly one extra
  fetch (asserted against the simulator's request counter).
* **Start-rate cooldown ≥5 s.** `_next_auto_refresh_at = start + 5` is set when
  *any* refresh starts, admin refreshes included. Automatic refreshes therefore
  cannot be started faster than once per 5 s no matter how many distinct kids an
  attacker sends; a 200-kid flood over 3 s produces **zero** additional fetches,
  and after the window exactly one more.
* **Non-blocking fast path.** A kid present in a fresh snapshot returns while
  holding the lock only for a dictionary lookup. While an unrelated refresh is
  blocked inside the simulator, 20 sequential cached verifications complete
  with zero network requests in well under 0.5 s (measured).
* **Admin forced refresh.** `POST /admin/refresh` bypasses the cooldown, does
  the fetch itself, and does not return until the result has been published or
  has failed. It does not wait for an in-flight *automatic* fetch; instead it
  **supersedes** it. Concurrent admin calls are single-flight with each other
  (a joining caller observes the same `op_id`).

### Anti-overwrite rule (the interleaving the task asks for)

Each operation gets a strictly increasing `op_id` at start; a published
snapshot's `seq` is that `op_id`. On completion the result is published only if

```
not op.superseded  and  op.op_id > published_seq
```

Otherwise the result is discarded (`discarded` counter in `/admin/status`).
Because publication is guarded by a monotonic generation, a response that
arrives later can never replace a newer snapshot, independent of arrival order.
A superseded operation's error is also not recorded as `last_error`, and its
waiters re-resolve against whatever snapshot is published.

The simulator supports this precisely: **on arrival** it captures the response
bytes/status for that request, then may block that request on its own release
event, then writes exactly the captured bytes. Two tests build the required
interleavings on top of that:

1. `test_old_response_cannot_overwrite_newer_snapshot` — automatic refresh is
   held after capturing *body A*; an admin refresh then fetches and publishes
   *body B*; the held A response is released afterwards. The final snapshot is
   B, the old token is rejected with `signature_invalid`, `discarded >= 1`.
2. `test_admin_refresh_joining_inflight_admin_op` and
   `test_auto_waiters_joined_to_superseded_op_use_newer_snapshot` — joiners
   observe one published `op_id`; waiters attached to a superseded operation
   are never handed its error and end up `unknown_kid` against the newer
   snapshot, never a stale success.

---

## 6. HTTP API

| Method | Path | Notes |
|---|---|---|
| `GET` | `/healthz` | liveness, no auth |
| `POST` | `/verify` | `Authorization: Bearer <jwt>` → 200 / 401 / 503 |
| `GET` | `/admin/status` | per-issuer snapshot, counters, in-flight op |
| `POST` | `/admin/refresh` | optional `{"issuer": "..."}`; blocks until done |

Admin endpoints require `Authorization: Bearer <admin_token>`; comparison is
constant-time. Errors are `{"valid": false, "error": "<stable code>"}` and
never contain token or key material. Bodies are capped at 16 KiB, the
authorization header at 20 KiB, and concurrent `/verify` calls at 256.

Machine-readable verification error codes: `missing_authorization`,
`unsupported_authorization_scheme`, `token_bad_segments`,
`token_empty_segment`, `token_too_large`, `token_whitespace`,
`b64url_bad_charset`, `b64url_bad_length`, `b64url_not_canonical`,
`json_invalid`, `json_duplicate_member`, `json_not_object`,
`json_member_not_integer`, `algorithm_not_allowed`, `unsupported_crit`,
`missing_kid`, `invalid_kid`, `invalid_iss`, `invalid_sub`, `invalid_aud`,
`missing_exp`, `missing_nbf`, `token_not_yet_valid`, `token_expired`,
`unknown_issuer`, `unknown_kid`, `signature_invalid`, `keys_unavailable`.

---

## 7. Test inventory and actual results

`python -m pytest tests -q` → **153 passed** (≈67 s on Windows 11 / Python
3.12.8, CPU only). The
same result was reproduced in a venv created from the designated runtime
(`D:/CC_Codex_FeedBack/runtimes/cc005-csv-python312/python.exe`, 3.12.8) with an
offline install from `vendor/wheels`.
`python scripts/demo.py` → **14/14 checks**.

| File | Tests | Covers |
|---|---|---|
| `test_token_rules.py` | 37 | strict JSON/base64url, alg/crit/jku, claims, integer time fields, `nbf`/`exp` boundaries, audience, tampering, real signature checks |
| `test_jwks_document.py` | 32 | whole-document rejection, duplicate kid, EC/private/small/large keys, count/byte limits, atomic no-partial-update, failure/expiry behaviour |
| `test_cache_rotation.py` | 15 | TTL boundary, rotated-out kid, same kid new key, no result caching, fetch timeout, slow refresh vs cached traffic, late-response ordering, admin cooldown bypass, per-issuer isolation |
| `test_concurrency.py` | 9 | 64 parallel cold verifications (1 fetch/issuer), 128 random unknown kids (1 fetch), cooldown under kid flood, per-issuer cooldown, 64 waiters fail closed, 64 parallel mixed old/new tokens |
| `test_refresh_interleavings.py` | 2 | admin joining admin, waiters on a superseded automatic op |
| `test_http_service.py` | 17 | real-socket happy paths and errors, admin auth/status/refresh, fail-closed 503, 64 parallel HTTP verifications, rotation via HTTP |
| `test_fetch.py` | 7 | pinned URL, no redirects, size cap, non-200, empty body, no credentials forwarded |
| `test_config_cli.py` | 25 | config validation, keystore round-trip, token generator output verified independently, subprocess invocation |
| `test_e2e_process.py` | 3 | service and token generator launched as real child processes; rotation and admin failures across the process boundary |
| `test_validation_order.py` | 6 | untrusted issuer / audience / expired / bad-alg rejections cause **zero** JWKS fetches |

The concurrency/coalescing claims are checked against the simulator's per-path
request counter and against actual RSA verification outcomes, not against
sleeps or log lines. Every "accepted" assertion is the result of a real
signature verification; every "rejected" assertion is a specific error code.

### Known limitations / not done

* Keys are RSA only and algorithms are RS256 only, per the task. There is no
  `PS256`, no EC, no encrypted JWTs, and no `jku`-based discovery (by design).
* Only plain `http://` JWKS URLs are fetched; TLS is not implemented because
  the scope is a local simulator. The configuration layer accepts `https`
  but the built-in fetcher refuses it rather than silently downgrading.
* Snapshot refresh is request-driven (plus the admin endpoint). There is no
  background timer that refreshes a snapshot before expiry; a cached,
  still-fresh snapshot is served until it expires.
* The service is single-process and in-memory. There is no persistence, no
  multi-process coordination, and no rate limiting on `/verify` beyond the
  256-concurrency cap and the refresh cooldown. Because refresh waiting is
  bounded (about 6 s with the default 2 s fetch timeout), a request that joins
  an in-flight refresh fails closed on timeout rather than waiting forever —
  this is deliberate (bounded latency) and tested.
* `/admin/status` reports internal counters (fetch attempts, published,
  discarded, in-flight op id, waiters). That is diagnostics for a local
  service, not a production API.
* `state/test-keys.json` contains private test keys by necessity; it is
  git-ignored and must never be reused outside this demo.
