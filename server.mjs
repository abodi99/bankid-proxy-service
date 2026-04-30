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

function getCredentials(env) {
  const s = env === "prod" ? "PROD" : "TEST";
  const certB64 = process.env[`BANKID_CERT_PEM_B64_${s}`];
  const keyB64 = process.env[`BANKID_KEY_PEM_B64_${s}`];
  if (certB64 && keyB64) return { cert: b64decode(certB64), key: b64decode(keyB64) };

  const pfxB64 = process.env[`BANKID_PFX_${s}`];
  const passphrase = process.env[`BANKID_PASSPHRASE_${s}`];
  if (pfxB64 && passphrase) {
    return { pfx: Buffer.from(pfxB64.replace(/\s+/g, ""), "base64"), passphrase };
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
  if (req.url === "/health") return;
  if (!PROXY_SECRET) return;
  const incoming = String(req.headers["x-proxy-secret"] || "");
  if (incoming !== PROXY_SECRET) {
    return reply.code(403).send({ error: "forbidden" });
  }
});

app.get("/health", async () => ({ status: "ok", timestamp: new Date().toISOString() }));

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
