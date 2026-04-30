/**
 * BankID Fastify proxy — RP-API v6 over mTLS (same material model as Zawajj `callBankIdCert.js`).
 *
 * Zawajj Firebase parity: POST /bankIdApiCallCert
 * Body: { endpoint: "FederatedLogin" | "GetSession", params: { useProduction?, endUserIp?, sessionId? } }
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

  throw new Error(`missing_bankid_credentials_${s}`);
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

function bankIdRequest(env, path, payload) {
  return new Promise((resolve, reject) => {
    const creds = getCredentials(env);
    const ca = getCa(env);
    const body = JSON.stringify(payload);

    const req = httpsRequest(
      {
        hostname: HOSTS[env],
        port: 443,
        path: `/rp/v6.0${path}`,
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
          try {
            resolve({ statusCode: res.statusCode || 500, body: JSON.parse(raw), raw });
          } catch {
            resolve({ statusCode: res.statusCode || 500, body: raw, raw });
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

/**
 * Zawajj `bankIdApiCallCert` callable contract (HTTP JSON instead of Firebase).
 * Same endpoints: FederatedLogin, GetSession.
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
    const endUserIp = getEndUserIp(params, req);
    try {
      const result = await bankIdRequest(env, "/auth", { endUserIp });
      if (result.statusCode !== 200) {
        return reply.code(502).send({
          error: "failed-precondition",
          message: `BankID auth: ${typeof result.body === "object" ? JSON.stringify(result.body) : result.raw}`,
        });
      }
      return reply.send({
        sessionId: result.body.orderRef,
        autoStartToken: result.body.autoStartToken,
      });
    } catch (err) {
      req.log.error(err);
      return reply.code(502).send({
        error: "failed-precondition",
        message: `BankID auth: ${err?.message || String(err)}`,
      });
    }
  }

  if (endpoint === "GetSession") {
    const orderRef = params.sessionId;
    if (!orderRef) {
      return reply.code(400).send({ error: "invalid-argument", message: "params.sessionId is required for GetSession" });
    }
    const endUserIp = getEndUserIp(params, req);
    try {
      const result = await bankIdRequest(env, "/collect", { orderRef });
      if (result.statusCode !== 200) {
        return reply.code(502).send({
          error: "failed-precondition",
          message: `BankID collect: ${typeof result.body === "object" ? JSON.stringify(result.body) : result.raw}`,
        });
      }
      const { status, hintCode, completionData } = result.body;

      if (status === "complete" && completionData?.user) {
        const user = completionData.user;
        return reply.send({
          userAttributes: {
            personalNumber: user.personalNumber || "",
            name: user.name || "",
            ipAddress: endUserIp,
          },
        });
      }

      if (status === "pending" || status === "failed") {
        return reply.send({
          grandidObject: {
            message: {
              status,
              hintCode: hintCode || "",
            },
          },
        });
      }

      return reply.send({
        grandidObject: {
          message: {
            status: status || "unknown",
            hintCode: hintCode || "",
          },
        },
      });
    } catch (err) {
      req.log.error(err);
      return reply.code(502).send({
        error: "failed-precondition",
        message: `BankID collect: ${err?.message || String(err)}`,
      });
    }
  }

  return reply.code(400).send({ error: "invalid-argument", message: `Unknown endpoint: ${endpoint}` });
});

app.post("/auth", async (req, reply) => {
  const body = req.body || {};
  const env = body.useProduction === true ? "prod" : "test";

  const payload = {
    endUserIp: String(body.endUserIp || "127.0.0.1"),
  };

  if (body.returnUrl) payload.returnUrl = body.returnUrl;
  if (body.userVisibleData) {
    payload.userVisibleData = Buffer.from(String(body.userVisibleData), "utf8").toString("base64");
  }
  if (body.app && typeof body.app === "object" && Object.keys(body.app).length > 0) {
    payload.app = body.app;
  }

  try {
    const result = await bankIdRequest(env, "/auth", payload);
    if (result.statusCode !== 200) {
      return reply.code(result.statusCode).send({
        error: "bankid_start_failed",
        message: typeof result.body === "object" ? JSON.stringify(result.body) : result.raw,
      });
    }

    return reply.send({
      sessionId: result.body.orderRef,
      autoStartToken: result.body.autoStartToken,
      qrStartToken: result.body.qrStartToken,
      qrStartSecret: result.body.qrStartSecret,
    });
  } catch (err) {
    req.log.error(err);
    return reply.code(502).send({ error: "bankid_start_failed", message: err?.message || String(err) });
  }
});

app.post("/collect", async (req, reply) => {
  const body = req.body || {};
  const sessionId = String(body.sessionId || "").trim();
  if (!sessionId) return reply.code(400).send({ error: "missing_session_id" });

  const env = body.useProduction === true ? "prod" : "test";
  const endUserIp = String(body.endUserIp || "127.0.0.1");

  try {
    const result = await bankIdRequest(env, "/collect", { orderRef: sessionId });
    if (result.statusCode !== 200) {
      return reply.code(result.statusCode).send({
        error: "bankid_collect_failed",
        message: typeof result.body === "object" ? JSON.stringify(result.body) : result.raw,
      });
    }

    const { status, hintCode, completionData } = result.body;
    if (status === "complete" && completionData?.user) {
      const { personalNumber, name } = completionData.user;
      const auth = await upsertAuthUser(personalNumber, name);
      return reply.send({
        status: "complete",
        userAttributes: { personalNumber, name, ipAddress: endUserIp },
        bankidSubject: auth.bankIdSubject,
        authCredentials: { email: auth.email, password: auth.password },
      });
    }

    return reply.send({ status, hintCode: hintCode || "" });
  } catch (err) {
    req.log.error(err);
    return reply.code(502).send({ error: "bankid_collect_failed", message: err?.message || String(err) });
  }
});

app.listen({ host: "0.0.0.0", port: PORT }).catch((err) => {
  app.log.error(err);
  process.exit(1);
});
