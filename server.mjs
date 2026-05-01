/**
 * BankID Fastify proxy — RP-API over mTLS (default path /rp/v6.0; override with BANKID_RP_API_PATH when BankID publishes a successor).
 * Align optional /auth fields with https://developers.bankid.com (endUserIp required; returnUrl, returnRisk, app|web, requirement, userVisibleData, …).
 * Do not strip unknown JSON keys from BankID responses at the HTTP layer; callers should tolerate new fields.
 *
 * Zawajj Firebase parity: POST /bankIdApiCallCert
 * Body: { endpoint: "FederatedLogin" | "GetSession" | "Cancel", params: { useProduction?, endUserIp?, sessionId? | orderRef?, … } }
 *
 * Local: leave PROXY_SECRET unset to skip auth on all routes (dev only).
 */
import Fastify from "fastify";
import { request as httpsRequest } from "node:https";
import { randomUUID } from "node:crypto";
import { createClient } from "@supabase/supabase-js";

const app = Fastify({ logger: true });
const PORT = Number(process.env.PORT || 3000);
const PROXY_SECRET = process.env.PROXY_SECRET || "";

const HOSTS = {
  prod: "appapi2.bankid.com",
  test: "appapi2.test.bankid.com",
};

/** Base path for RP API (e.g. /rp/v6.0). Bump when BankID documents a new breaking URL. */
const BANKID_RP_BASE = (process.env.BANKID_RP_API_PATH || "/rp/v6.0").replace(/\/$/, "");

function b64decode(value) {
  return Buffer.from(String(value || "").replace(/\s+/g, ""), "base64").toString("utf8");
}

/** Zawajj test secrets: BANKID_PFX + BANKID_PASSPHRASE. Our stack: BANKID_PFX_TEST + BANKID_PASSPHRASE_TEST. */
function getCredentials(env) {
  const s = env === "prod" ? "PROD" : "TEST";
  const certB64 = process.env[`BANKID_CERT_PEM_B64_${s}`];
  const keyB64 = process.env[`BANKID_KEY_PEM_B64_${s}`];
  if (certB64 && keyB64) return { cert: b64decode(certB64), key: b64decode(keyB64) };

  if (env === "prod") {
    const pfxB64 = process.env.BANKID_PFX_PROD;
    const passphrase = process.env.BANKID_PASSPHRASE_PROD;
    if (pfxB64 && passphrase) {
      return { pfx: Buffer.from(String(pfxB64).replace(/\s+/g, ""), "base64"), passphrase };
    }
  } else {
    const pfxB64 = process.env.BANKID_PFX_TEST || process.env.BANKID_PFX;
    const passphrase = process.env.BANKID_PASSPHRASE_TEST || process.env.BANKID_PASSPHRASE;
    if (pfxB64 && passphrase) {
      return { pfx: Buffer.from(String(pfxB64).replace(/\s+/g, ""), "base64"), passphrase };
    }
  }

  const hint =
    env === "prod"
      ? " Set BANKID_PFX_PROD + BANKID_PASSPHRASE_PROD (or BANKID_CERT_PEM_B64_PROD + BANKID_KEY_PEM_B64_PROD). Start with: node --env-file=.env server.mjs"
      : " Set BANKID_PFX_TEST + BANKID_PASSPHRASE_TEST or Zawajj-style BANKID_PFX + BANKID_PASSPHRASE.";
  throw new Error(`missing_bankid_credentials_${s}.${hint}`);
}

function getCa(env) {
  const s = env === "prod" ? "PROD" : "TEST";
  const caB64 = process.env[`BANKID_CA_${s}_B64`];
  if (caB64) return b64decode(caB64);
  const caText = process.env[`BANKID_CA_${s}`];
  if (caText && caText.includes("BEGIN CERTIFICATE")) return caText;
  if (env === "test") return undefined;
  throw new Error("missing_bankid_ca_prod");
}

function getEndUserIp(params, req) {
  const fromParams = params && typeof params.endUserIp === "string" ? params.endUserIp.trim() : "";
  if (fromParams) return fromParams;
  const raw = req.socket?.remoteAddress || "";
  if (raw && raw.startsWith("::ffff:")) return raw.slice(7);
  if (raw) return raw;
  return "127.0.0.1";
}

function toBase64Utf8(value) {
  return Buffer.from(String(value), "utf8").toString("base64");
}

/**
 * Build BankID POST /auth body (RP API). Passes through documented optional fields when present.
 * userVisibleData / userNonVisibleData: plain UTF-8 strings are base64-encoded for BankID.
 * Use *Base64 suffix to send values already encoded per BankID (no second encoding).
 */
function buildAuthPayload(source, req) {
  const s = source && typeof source === "object" ? source : {};
  const payload = { endUserIp: getEndUserIp(s, req) };

  if (typeof s.returnUrl === "string" && s.returnUrl.trim()) payload.returnUrl = s.returnUrl.trim();
  if (s.returnRisk === true) payload.returnRisk = true;

  if (s.requirement && typeof s.requirement === "object" && Object.keys(s.requirement).length > 0) {
    payload.requirement = s.requirement;
  }

  const app = s.app && typeof s.app === "object" ? s.app : null;
  const web = s.web && typeof s.web === "object" ? s.web : null;
  if (app && Object.keys(app).length > 0) payload.app = app;
  if (web && Object.keys(web).length > 0) payload.web = web;

  if (typeof s.userVisibleDataBase64 === "string" && s.userVisibleDataBase64.trim()) {
    payload.userVisibleData = String(s.userVisibleDataBase64).replace(/\s+/g, "");
  } else if (s.userVisibleData != null && String(s.userVisibleData).length > 0) {
    payload.userVisibleData = toBase64Utf8(s.userVisibleData);
  }

  if (typeof s.userNonVisibleDataBase64 === "string" && s.userNonVisibleDataBase64.trim()) {
    payload.userNonVisibleData = String(s.userNonVisibleDataBase64).replace(/\s+/g, "");
  } else if (s.userNonVisibleData != null && String(s.userNonVisibleData).length > 0) {
    payload.userNonVisibleData = toBase64Utf8(s.userNonVisibleData);
  }

  // BankID /auth and /sign: e.g. "simpleMarkdownV1" when userVisibleData uses that format (XML signature records format=…; element still holds exact payload).
  if (typeof s.userVisibleDataFormat === "string" && s.userVisibleDataFormat.trim()) {
    payload.userVisibleDataFormat = s.userVisibleDataFormat.trim();
  }

  return payload;
}

/**
 * Documented RP-API HTTP error `errorCode` values (auth/sign/collect/cancel).
 * New codes may appear without notice — unknown 400 → hint RFA22 per BankID.
 */
const BANKID_KNOWN_ERROR_CODES = new Set([
  "alreadyInProgress",
  "invalidParameters",
  "unauthorized",
  "notFound",
  "methodNotAllowed",
  "requestTimeout",
  "unsupportedMediaType",
  "internalError",
  "maintenance",
]);

/**
 * Optional hint for end-user copy (RFA*). Do not show raw BankID `details` for internal-only cases.
 * See BankID "Errors" — RP action / user messages.
 */
function attachBankIdUserMessageHint(httpStatus, payload) {
  if (!payload || typeof payload !== "object") return;
  const ec = payload.errorCode != null ? String(payload.errorCode) : "";

  if (httpStatus === 400 && ec === "alreadyInProgress") {
    payload.userMessageHint = "RFA4";
    return;
  }
  if (httpStatus === 408 || httpStatus === 500) {
    payload.userMessageHint = "RFA5";
    return;
  }
  if (httpStatus === 503) {
    payload.userMessageHint = "RFA5";
    payload.retryWithoutUserMessageFirst = true;
    return;
  }
  if (httpStatus === 400) {
    if (!ec || !BANKID_KNOWN_ERROR_CODES.has(ec)) {
      payload.userMessageHint = "RFA22";
    }
  }
}

/**
 * Reply with BankID upstream failure: preserve HTTP status + JSON body (`errorCode`, `details`, …).
 * Non-JSON bodies become a small structured error. Adds `userMessageHint` when applicable.
 */
function replyBankIdFailure(reply, result, logLabel) {
  const code =
    typeof result.statusCode === "number" && result.statusCode >= 400 && result.statusCode < 600
      ? result.statusCode
      : 502;

  let payload;
  if (result.body && typeof result.body === "object") {
    payload = { ...result.body };
    attachBankIdUserMessageHint(code, payload);
  } else if (typeof result.body === "string" && result.body.length > 0) {
    payload = {
      errorCode: "invalidResponse",
      details: result.body.slice(0, 2000),
    };
    attachBankIdUserMessageHint(code, payload);
  } else {
    payload = {
      errorCode: "upstreamError",
      details: typeof result.raw === "string" ? result.raw : "",
    };
    attachBankIdUserMessageHint(code, payload);
  }

  if (logLabel) {
    reply.request.log.warn({ bankId: logLabel, httpStatus: code, bankIdError: payload }, "BankID upstream error");
  }
  return reply.code(code).send(payload);
}

function bankIdRequest(env, path, payload) {
  return new Promise((resolve, reject) => {
    const creds = getCredentials(env);
    const ca = getCa(env);
    const body = JSON.stringify(payload);

    const req = httpsRequest(
      {
        hostname: HOSTS[env],
        port: 443,
        path: `${BANKID_RP_BASE}${path}`,
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Content-Length": Buffer.byteLength(body, "utf8"),
        },
        ...(creds.pfx ? { pfx: creds.pfx, passphrase: creds.passphrase } : { cert: creds.cert, key: creds.key }),
        ...(ca ? { ca } : {}),
        rejectUnauthorized: true,
      },
      (res) => {
        const chunks = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => {
          const raw = Buffer.concat(chunks).toString("utf8");
          const code = res.statusCode || 500;
          if (!raw.trim()) {
            resolve({ statusCode: code, body: null, raw: "" });
            return;
          }
          try {
            resolve({ statusCode: code, body: JSON.parse(raw), raw });
          } catch {
            resolve({ statusCode: code, body: raw, raw });
          }
        });
      },
    );

    req.on("error", reject);
    req.write(body);
    req.end();
  });
}

function serviceClient() {
  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!url || !key) throw new Error("missing_supabase_env");
  return createClient(url, key, { auth: { persistSession: false, autoRefreshToken: false } });
}

function normalizePnr(pnr) {
  return String(pnr || "").replace(/[^0-9]/g, "");
}

async function upsertAuthUser(personalNumber, name) {
  const supabase = serviceClient();
  const normalized = normalizePnr(personalNumber);
  if (normalized.length < 8) throw new Error("invalid_personal_number");

  const email = `bankid.${normalized}@volontera.local`;
  const password = `${randomUUID()}A!9`;
  const bankIdSubject = `bankid:pnr:${normalized}`;

  const listed = await supabase.auth.admin.listUsers({ page: 1, perPage: 1000 });
  if (listed.error) throw listed.error;
  const existing = listed.data.users.find((u) => u.email === email);

  if (!existing) {
    const created = await supabase.auth.admin.createUser({
      email,
      password,
      email_confirm: true,
      app_metadata: { bankid_subject: bankIdSubject },
      user_metadata: { bankid_name: name, personal_number: normalized },
    });
    if (created.error) throw created.error;
  } else {
    const updated = await supabase.auth.admin.updateUserById(existing.id, {
      password,
      app_metadata: { bankid_subject: bankIdSubject },
      user_metadata: { bankid_name: name, personal_number: normalized },
    });
    if (updated.error) throw updated.error;
  }

  return { email, password, bankIdSubject };
}

app.addHook("onRequest", async (req, reply) => {
  if (req.url === "/health" || req.url === "/") return;
  if (!PROXY_SECRET) return;

  const authHeader = req.headers["authorization"];
  const proxyHeader = req.headers["x-proxy-secret"];
  
  let incoming = "";
  if (authHeader && authHeader.startsWith("Bearer ")) {
    incoming = authHeader.substring(7);
  } else if (proxyHeader) {
    incoming = String(proxyHeader);
  }

  if (incoming !== PROXY_SECRET) {
    req.log.warn({ url: req.url, headers: req.headers }, "Unauthorized access attempt");
    return reply.code(403).send({ error: "forbidden", message: "Invalid proxy secret" });
  }
});

app.get("/health", async () => ({ status: "ok", timestamp: new Date().toISOString() }));

function resolveOrderRef(params, body) {
  const p = params && typeof params === "object" ? params : {};
  const b = body && typeof body === "object" ? body : {};
  const ref = p.orderRef ?? p.sessionId ?? b.orderRef ?? b.sessionId;
  return ref != null && String(ref).trim() ? String(ref).trim() : "";
}

/**
 * Zawajj `bankIdApiCallCert` callable contract (HTTP JSON instead of Firebase).
 * Endpoints: FederatedLogin, GetSession (collect), Cancel.
 */
app.post("/bankIdApiCallCert", async (req, reply) => {
  const body = req.body || {};
  const { endpoint, params } = body;
  if (!endpoint || !params || typeof params !== "object") {
    return reply.code(400).send({ error: "invalid-argument", message: "endpoint and params are required" });
  }

  const useProduction = params.useProduction === true;
  const env = useProduction ? "prod" : "test";

  if (endpoint === "FederatedLogin") {
    try {
      const authPayload = buildAuthPayload(params, req);
      const result = await bankIdRequest(env, "/auth", authPayload);
      if (result.statusCode !== 200) {
        return replyBankIdFailure(reply, result, "bankIdApiCallCert.auth");
      }
      const b = result.body && typeof result.body === "object" ? result.body : {};
      const out = {
        sessionId: b.orderRef,
        autoStartToken: b.autoStartToken,
      };
      if (b.qrStartToken) out.qrStartToken = b.qrStartToken;
      if (b.qrStartSecret) out.qrStartSecret = b.qrStartSecret;
      return reply.send(out);
    } catch (err) {
      req.log.error(err);
      return reply.code(502).send({
        error: "failed-precondition",
        message: `BankID auth: ${err?.message || String(err)}`,
      });
    }
  }

  if (endpoint === "GetSession") {
    const orderRef = resolveOrderRef(params, {});
    if (!orderRef) {
      return reply.code(400).send({
        error: "invalid-argument",
        message: "params.orderRef or params.sessionId is required for GetSession",
      });
    }
    const endUserIp = getEndUserIp(params, req);
    try {
      const result = await bankIdRequest(env, "/collect", { orderRef });
      if (result.statusCode !== 200) {
        return replyBankIdFailure(reply, result, "bankIdApiCallCert.collect");
      }
      const collectBody = result.body && typeof result.body === "object" ? result.body : {};
      const { status, hintCode, completionData } = collectBody;

      if (status === "complete" && completionData?.user) {
        const user = completionData.user;
        return reply.send({
          userAttributes: {
            personalNumber: user.personalNumber || "",
            name: user.name || "",
            ipAddress: endUserIp,
          },
          ...(completionData && typeof completionData === "object" ? { completionData } : {}),
          bankidCollect: collectBody,
        });
      }

      if (status === "pending" || status === "failed") {
        return reply.send({
          grandidObject: {
            message: {
              orderRef: collectBody.orderRef || orderRef,
              status,
              hintCode: hintCode || "",
            },
          },
          bankidCollect: collectBody,
        });
      }

      return reply.send({
        grandidObject: {
          message: {
            orderRef: collectBody.orderRef || orderRef,
            status: status || "unknown",
            hintCode: hintCode || "",
          },
        },
        bankidCollect: collectBody,
      });
    } catch (err) {
      req.log.error(err);
      return reply.code(502).send({
        error: "failed-precondition",
        message: `BankID collect: ${err?.message || String(err)}`,
      });
    }
  }

  if (endpoint === "Cancel") {
    const orderRef = resolveOrderRef(params, {});
    if (!orderRef) {
      return reply.code(400).send({
        error: "invalid-argument",
        message: "params.orderRef or params.sessionId is required for Cancel",
      });
    }
    try {
      const result = await bankIdRequest(env, "/cancel", { orderRef });
      if (result.statusCode !== 200) {
        return replyBankIdFailure(reply, result, "bankIdApiCallCert.cancel");
      }
      return reply.code(200).send();
    } catch (err) {
      req.log.error(err);
      return reply.code(502).send({
        error: "failed-precondition",
        message: `BankID cancel: ${err?.message || String(err)}`,
      });
    }
  }

  return reply.code(400).send({ error: "invalid-argument", message: `Unknown endpoint: ${endpoint}` });
});

app.post("/auth", async (req, reply) => {
  const body = req.body || {};
  const env = body.useProduction === true ? "prod" : "test";
  const { useProduction: _u, ...authSource } = body;
  const payload = buildAuthPayload(authSource, req);

  try {
    const result = await bankIdRequest(env, "/auth", payload);
    if (result.statusCode !== 200) {
      return replyBankIdFailure(reply, result, "auth");
    }

    const b = result.body && typeof result.body === "object" ? result.body : {};
    return reply.send({
      sessionId: b.orderRef,
      autoStartToken: b.autoStartToken,
      qrStartToken: b.qrStartToken,
      qrStartSecret: b.qrStartSecret,
    });
  } catch (err) {
    req.log.error(err);
    return reply.code(502).send({ error: "bankid_start_failed", message: err?.message || String(err) });
  }
});

app.post("/collect", async (req, reply) => {
  const body = req.body || {};
  const orderRef = resolveOrderRef({}, body);
  if (!orderRef) {
    return reply.code(400).send({
      error: "missing_order_ref",
      message: "orderRef is required (or sessionId for backward compatibility)",
    });
  }

  const env = body.useProduction === true ? "prod" : "test";
  const endUserIp = String(body.endUserIp || "127.0.0.1");

  try {
    const result = await bankIdRequest(env, "/collect", { orderRef });
    if (result.statusCode !== 200) {
      return replyBankIdFailure(reply, result, "collect");
    }

    const collectBody = result.body && typeof result.body === "object" && result.body !== null ? result.body : {};
    const { status, hintCode, completionData } = collectBody;

    if (status === "complete" && completionData?.user) {
      const { personalNumber, name } = completionData.user;
      const auth = await upsertAuthUser(personalNumber, name);
      return reply.send({
        orderRef: collectBody.orderRef || orderRef,
        status: "complete",
        userAttributes: { personalNumber, name, ipAddress: endUserIp },
        bankidSubject: auth.bankIdSubject,
        authCredentials: { email: auth.email, password: auth.password },
        ...(completionData && typeof completionData === "object" ? { completionData } : {}),
      });
    }

    if (Object.keys(collectBody).length > 0) {
      return reply.send(collectBody);
    }
    return reply.send({ orderRef, status, hintCode: hintCode || "" });
  } catch (err) {
    req.log.error(err);
    return reply.code(502).send({ error: "bankid_collect_failed", message: err?.message || String(err) });
  }
});

app.post("/cancel", async (req, reply) => {
  const body = req.body || {};
  const orderRef = resolveOrderRef({}, body);
  if (!orderRef) {
    return reply.code(400).send({
      error: "missing_order_ref",
      message: "orderRef is required (or sessionId for backward compatibility)",
    });
  }

  const env = body.useProduction === true ? "prod" : "test";

  try {
    const result = await bankIdRequest(env, "/cancel", { orderRef });
    if (result.statusCode !== 200) {
      return replyBankIdFailure(reply, result, "cancel");
    }
    return reply.code(200).send();
  } catch (err) {
    req.log.error(err);
    return reply.code(502).send({ error: "bankid_cancel_failed", message: err?.message || String(err) });
  }
});

app.listen({ host: "0.0.0.0", port: PORT }).catch((err) => {
  app.log.error(err);
  process.exit(1);
});
