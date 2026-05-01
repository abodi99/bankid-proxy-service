# bankid-proxy-service

Fastify proxy service for BankID RP API v6 with mTLS and Supabase user provisioning.

## Local run

Load `.env` and watch for changes:

```bash
npm run dev:local
```

Leave `PROXY_SECRET` empty in `.env` during local development to skip proxy auth on all routes (see `server.mjs`).

Encode a `.pfx` to a single line for `BANKID_PFX_PROD`:

```bash
npm run encode:pfx -- path/to/bankid.pfx
# or: ./scripts/encode-pfx-b64.sh path/to/bankid.pfx
```

### BankID `/auth` fields (proxy → RP API)

The proxy builds the JSON body for BankID `POST …/auth` from your request. Supported fields (see [BankID developer docs](https://developers.bankid.com)):

| Field | Notes |
|--------|--------|
| `endUserIp` | Required; end user’s IP as seen by **your** service (not only the proxy). |
| `returnUrl` | Optional; **from RP-API v6, send on the server** in `POST …/auth` (not in the autostart URL — that is deprecated). Strongly recommended for same-device flows: BankID opens this URL after completion; mitigates some session fixation. Use HTTPS with a **nonce in the fragment** (see [Return URL](#return-url-rp-api-v6) below). |
| `returnRisk` | Optional boolean; risk may appear in `collect` / `completionData` when the order completes. |
| `app` or `web` | Optional objects; send **one** of them per BankID rules, with at least one member. |
| `requirement` | Optional (e.g. `personalNumber`). |
| `userVisibleData` | Plain UTF-8 text; the proxy **base64-encodes** it for BankID (same as sending `userVisibleData` in RP-API JSON). |
| `userNonVisibleData` | Plain text; encoded to base64 for BankID. |
| `userVisibleDataBase64` / `userNonVisibleDataBase64` | Values **already** base64-encoded for BankID (no second encoding). Use this if you build the exact bytes yourself (e.g. matching BankID examples). |
| `userVisibleDataFormat` | Optional on BankID **`/auth`** and **`/sign`**. Set to **`simpleMarkdownV1`** when `userVisibleData` uses that format (see [Simple Markdown v1](#simple-markdown-v1) below). **Signing:** XML may include `format="simpleMarkdownV1"`; the signed **`userVisibleData`** payload is still **exactly** what you sent. This repo proxies **`/auth`** only; the same field applies if you add **`/sign`**. |

For `POST /bankIdApiCallCert` with `endpoint: "FederatedLogin"`, pass these inside `params` (along with `useProduction`, etc.). Successful responses include `qrStartToken` and `qrStartSecret` when BankID returns them (e.g. QR flows). On `GetSession` when `status` is `complete`, `completionData` is included so clients can read e.g. risk data.

### Simple Markdown v1

When `userVisibleDataFormat` is **`simpleMarkdownV1`**, `userVisibleData` (after base64 decode) must follow BankID’s **Simple Markdown version 1** rules. Summary below; treat the **official BankID “Syntax, special characters and rendering”** as source of truth and test on real BankID clients.

**Encoding:** UTF-8. Allowed code points include U+0020–U+007E, U+00A0–U+FFEF, U+000A (newline), U+0009 (tab), U+000D (CR).

**Whitespace:** Space or tab; runs of whitespace render as **one** space; leading/trailing whitespace on a line is trimmed. **Avoid a trailing space after bold** — some client versions report an error.

**Lines:** “Line” is text between line endings (LF, CR, or CRLF) or end of document.

**Escaping:** Use `\` before `#`, `+`, `|`, `*`, `-`, or `\` for literals. `\` before any other character is **invalid**. The backslash is not shown when rendered.

**Headings:** Line starts with **1–3** `#`, then **one space**, then non-empty title text. Level = number of `#`.

**Thematic break:** A line that is exactly `---` (optional whitespace after).

**Tables:** Rows start and end with `|`; cells separated by `|`. Requires a **header** row, a **delimiter** row (cells are `-` with optional `:` for left / right / center alignment), then body rows. **At most 5 columns**; all rows same cell count. **Do not** put whitespace next to `|` inside cell content (some clients error). **Per cell:** either plain text **or** bold — **not both** in some clients.

**Lists:** **Unordered:** `+` + space + item text. **Ordered:** `+` + one or two digits (value ≥ 0) + space + item text; numbering may have gaps/duplicates; no redundant leading zeros. Item text cannot be empty or whitespace-only.

**Paragraphs:** Any line that is not a heading, `---`, table row, list line, or empty line.

**Empty lines:** Allowed; not rendered. They **separate** two tables or two lists of the **same** type.

**Strong emphasis (inline):** `*like this*` — no whitespace immediately after the opening `*` or before the closing `*`. Unclosed `*` makes the document invalid.

Invalid markup can cause the BankID app to reject or mis-render the text; validate and test end-to-end.

### Autostart (same device as BankID app)

Use the **`autoStartToken`** from the `/auth` response (this proxy exposes it as `autoStartToken` in JSON, or via `FederatedLogin` in `bankIdApiCallCert`). Official behaviour is described in BankID’s autostart guide; summary:

| Autostart URL param | Notes |
|---------------------|--------|
| `autostarttoken` | **Required** — value from the web service (`autoStartToken`). |
| `redirect` | **Optional, deprecated** — Prefer **`returnUrl` on the backend `POST …/auth` body** (see table above). Legacy: HTTPS, UTF-8, URL-encoded, or `null`. With `null`, the BankID app closes and the **calling app** typically regains focus (Android often uses `…&redirect=null`). **iOS:** `redirect=null` means your app/web is **not** opened via URL after completion; use **collect** (and universal links / URL scheme for your own return flow). |
| `rpref` | Optional; **not supported on mobile**. Base64 + URL-encoded, 8–255 bytes after encoding; included in signature when used. |

**Native iOS:** Open universal link  
`https://app.bankid.com/?autostarttoken=[TOKEN]`  
(e.g. `UIApplication.shared.open` with universal-links-only). If open fails, BankID is likely not installed. Register a universal link or custom URL scheme if you need the BankID app to bring the user back.

**Native Android:** `ACTION_VIEW` with  
`https://app.bankid.com/?autostarttoken=[TOKEN]&redirect=null`  
Catch **ActivityNotFoundException** if BankID is missing. **Do not rely on the activity result** from BankID — **poll `/collect`** for the real outcome.

**Browser on mobile:** Programmatic navigation to  
`https://app.bankid.com/?autostarttoken=[TOKEN]`  
with `referrerPolicy: "origin"` (iOS universal links / Android app links).

**Browser on desktop:**  
`bankid:///?autostarttoken=[TOKEN]`

**Flutter:** Same URLs as above (`url_launcher` or platform channels). Combine with **collect polling** as today; treat “launch failed” and “unknown completion” via **collect**, not only launch callbacks.

### Return URL (RP-API v6+)

BankID **strongly recommends** supplying **`returnUrl` in the `/auth` request body** (this proxy forwards it via `params.returnUrl` on `FederatedLogin` / `bankIdApiCallCert`, or `returnUrl` on `POST /auth`). Putting return URL only in the autostart link is **deprecated**.

**End-to-end (web):**

1. User is on your site (e.g. `https://www.example.com/login`).
2. Your backend calls RP-API `/auth` with `returnUrl` such as `https://www.example.com/login#nonce=[session-nonce]` (nonce generated server-side, bound to the session).
3. RP-API returns `autoStartToken`; the page starts BankID with `https://app.bankid.com/?autostarttoken=…` (no return in that URL when using server `returnUrl`).
4. After the user finishes in BankID, the **BankID app opens `returnUrl`** (often in the **system default browser** — see pitfalls below).
5. Your site **verifies the fragment nonce** matches the session, then completes login (and still use **`/collect`** as the source of truth for order outcome if you rely on RP-API).

**End-to-end (native app):**

1. App triggers server `/auth` with an **app-handled** URL, e.g. `https://app.example.com/login#nonce=…` or **`myapp://login#nonce=…`** (universal link or custom scheme registered to your app).
2. Receive `autoStartToken`, launch BankID autostart URL as above.
3. After completion, BankID invokes **`returnUrl`**; your app resumes and **verifies the nonce** matches what you stored for this order.

**Older desktop BankID clients** that cannot use server-side return URL may **cancel** the order and ask the user to update — plan for that in support copy.

**Pitfalls (web):**

- **Browser:** The return URL is opened in the **default** browser, not necessarily the one that started the flow. If a browser documents a custom scheme (BankID’s example: Chrome → `chromebrowser://www.example.com/…`), using that in `returnUrl` can improve routing; otherwise behaviour is device-dependent — **test real devices**.
- **Same tab:** Best chance to land in the “right” context is using the **exact page URL** as the base of `returnUrl`, with **`#nonce=…` in the fragment** so the nonce is not sent to the server on navigation but can be read by your JS. **Do not** put secrets or session cookies in the nonce; use an opaque server-issued token.

**This proxy:** Pass `returnUrl` like any other `/auth` field — e.g. `POST /bankIdApiCallCert` with `params: { …, "returnUrl": "https://your.app/path#nonce=abc" }`.

Optional: `BANKID_RP_API_PATH` (default `/rp/v6.0`) if BankID moves to a new version path.

### BankID HTTP errors (auth / sign / collect / cancel)

When BankID returns a non-**200** response, the proxy **forwards the same HTTP status** and, for JSON error bodies, the same fields BankID sends (e.g. `errorCode`, `details`). Example:

```json
HTTP/1.1 400 Bad Request
{ "errorCode": "invalidParameters", "details": "No such order" }
```

Your app should handle **new `errorCode` values** without prior notice (show a generic message; BankID suggests user message **RFA22** for unknown 400 errors). The proxy may add optional hints (not from BankID):

| Situation | `userMessageHint` (optional) |
|-----------|------------------------------|
| `400` + `alreadyInProgress` | `RFA4` |
| `400` + unknown / missing `errorCode` | `RFA22` |
| `408`, `500` | `RFA5` |
| `503` | `RFA5`; `retryWithoutUserMessageFirst: true` (retry silently first, per BankID) |

Do **not** expose raw BankID errors to end users for cases BankID marks as internal (e.g. `invalidParameters`, `401`/`403` `unauthorized`, wrong URL, wrong cert) — fix the integration instead. See BankID “Errors” in the official documentation.

## Endpoints
- `GET /health`
- `POST /bankIdApiCallCert` — same JSON contract as Zawajj Firebase `bankIdApiCallCert`:
  - `FederatedLogin`, `GetSession` (BankID **collect**), `Cancel`
  - `params.useProduction`, `params.endUserIp`; **`params.orderRef` or `params.sessionId`** for collect/cancel
  - Poll **collect** every ~2s while `status === "pending"`; stop on `failed`. Treat unknown `hintCode` per [BankID docs](https://developers.bankid.com). Full collect payload is also returned as `bankidCollect` where applicable.
- `POST /auth` — BankID `/auth`
- `POST /collect` — BankID `/collect`; JSON body **`orderRef`** (required). Legacy: **`sessionId`** accepted as alias.
- `POST /cancel` — BankID `/cancel`; body **`orderRef`** (or **`sessionId`**). **200** with empty body on success (matches BankID).

## Required environment variables (secrets / certificates)

**TLS client authentication to BankID (production):**

- `BANKID_PFX_PROD` — Base64-encoded **client PFX** (the certificate package from the bank that holds your BankID agreement). Same as Firebase `BANKID_PFX_PROD`.
- `BANKID_PASSPHRASE_PROD` — Passphrase for that PFX.
- `BANKID_CA_PROD` **or** `BANKID_CA_PROD_B64` — BankID **SSL root CA** PEM (or base64 of PEM) used to verify `appapi2.bankid.com`. Not your client cert; it pins the server chain.

**Test environment:** `BANKID_PFX` / `BANKID_PASSPHRASE` (or `BANKID_PFX_TEST` / …), optional test CA; host is `appapi2.test.bankid.com`.

**Alternative to PFX:** PEM client cert + key as `BANKID_CERT_PEM_B64_PROD` + `BANKID_KEY_PEM_B64_PROD` (or `_TEST`).

**Other:**

- `PORT` (default `3000`)
- `PROXY_SECRET` (optional locally; omit to disable auth)
- `SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY` (only for `POST /collect` when provisioning Supabase users)
- `BANKID_RP_API_PATH` (optional; default `/rp/v6.0`)
