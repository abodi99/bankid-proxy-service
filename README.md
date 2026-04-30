# bankid-proxy-service

Fastify proxy service for BankID RP API v6 with mTLS and Supabase user provisioning.

## Endpoints
- `GET /health`
- `POST /auth`
- `POST /collect`

## Required environment variables
- `PORT` (default `3000`)
- `PROXY_SECRET`
- `SUPABASE_URL`
- `SUPABASE_SERVICE_ROLE_KEY`
- `BANKID_PFX_PROD`, `BANKID_PASSPHRASE_PROD`
- `BANKID_CA_PROD` or `BANKID_CA_PROD_B64`

Optional test variables:
- `BANKID_PFX_TEST`, `BANKID_PASSPHRASE_TEST`
- `BANKID_CA_TEST`, `BANKID_CA_TEST_B64`
- Or PEM pair: `BANKID_CERT_PEM_B64_*` + `BANKID_KEY_PEM_B64_*`
