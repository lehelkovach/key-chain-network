#!/usr/bin/env bash
# End-to-end smoke test against a running KeyChain instance.
#
# Walks the full path an IAC-Bus deployment takes: bootstrap discovery, mint an
# orchestrator, delegate a worker beneath it, register through the ACP v2
# endpoint, issue and verify a capability token, then revoke and prove the token
# stops working.
#
#   KEYCHAIN_URL=http://127.0.0.1:8102 KEYCHAIN_API_TOKEN=devtoken \
#     bash scripts/keychain_smoke.sh
set -euo pipefail

KEYCHAIN_URL="${KEYCHAIN_URL:-http://127.0.0.1:${KEYCHAIN_PORT:-8102}}"
KEYCHAIN_API_TOKEN="${KEYCHAIN_API_TOKEN:-}"
REPO_LOCALE="${SMOKE_REPO_LOCALE:-smoke-$(date +%s)}"

if ! command -v jq >/dev/null 2>&1; then
  echo "FAIL: jq is required" >&2
  exit 1
fi

AUTH=()
if [[ -n "${KEYCHAIN_API_TOKEN}" ]]; then
  AUTH=(-H "Authorization: Bearer ${KEYCHAIN_API_TOKEN}")
fi

pass=0
fail=0

check() {
  local label="$1" actual="$2" expected="$3"
  if [[ "${actual}" == "${expected}" ]]; then
    printf 'ok   %-58s %s\n' "${label}" "${actual}"
    pass=$((pass + 1))
  else
    printf 'FAIL %-58s got %s want %s\n' "${label}" "${actual}" "${expected}"
    fail=$((fail + 1))
  fi
}

api() {
  local method="$1" path="$2" body="${3:-}"
  if [[ -n "${body}" ]]; then
    curl -sS -X "${method}" "${KEYCHAIN_URL}${path}" \
      -H 'Content-Type: application/json' "${AUTH[@]+"${AUTH[@]}"}" -d "${body}"
  else
    curl -sS -X "${method}" "${KEYCHAIN_URL}${path}" "${AUTH[@]+"${AUTH[@]}"}"
  fi
}

status() {
  local method="$1" path="$2" body="${3:-}"
  if [[ -n "${body}" ]]; then
    curl -sS -o /dev/null -w '%{http_code}' -X "${method}" "${KEYCHAIN_URL}${path}" \
      -H 'Content-Type: application/json' "${AUTH[@]+"${AUTH[@]}"}" -d "${body}"
  else
    curl -sS -o /dev/null -w '%{http_code}' -X "${method}" "${KEYCHAIN_URL}${path}" \
      "${AUTH[@]+"${AUTH[@]}"}"
  fi
}

echo "== KeyChain smoke against ${KEYCHAIN_URL} (repo_locale=${REPO_LOCALE})"

echo "-- discovery"
health="$(api GET /health)"
check "health status" "$(jq -r .status <<<"${health}")" "ok"
check "health names the service" "$(jq -r .service <<<"${health}")" "key-chain-network"
root_key_id="$(api GET /.well-known/keychain/roots.json | jq -r '.roots[0].key_id')"
check "a trust root is published" "$([[ -n "${root_key_id}" && "${root_key_id}" != "null" ]] && echo yes || echo no)" "yes"
check "jwks publishes no private keys" \
  "$(api GET /.well-known/keychain/jwks.json | jq '[.keys[] | has("d")] | any')" "false"

if [[ -n "${KEYCHAIN_API_TOKEN}" ]]; then
  echo "-- auth"
  check "unauthenticated mint is refused" \
    "$(curl -sS -o /dev/null -w '%{http_code}' -X POST "${KEYCHAIN_URL}/agents/mint" \
      -H 'Content-Type: application/json' -d '{}')" "401"
fi

echo "-- mint an orchestrator (key held by KeyChain so it can delegate)"
orchestrator="$(api POST /agents/mint "$(cat <<JSON
{"brand":"cursor","repo_locale":"${REPO_LOCALE}","role":"orchestrator",
 "medium":"api","custody":"keychain"}
JSON
)")"
check "orchestrator handle" "$(jq -r .logical_handle <<<"${orchestrator}")" \
  "agent:cursor.${REPO_LOCALE}.0"
check "orchestrator ordinal" "$(jq -r .ordinal_path <<<"${orchestrator}")" "0"
check "orchestrator may mint" \
  "$(jq '.capabilities | index("agent.mint") != null' <<<"${orchestrator}")" "true"
check "chain ends at a root" \
  "$(jq -r '.certificate_chain[-1].cert_type' <<<"${orchestrator}")" "root"
orchestrator_uuid="$(jq -r .agent_uuid <<<"${orchestrator}")"

echo "-- idempotency"
check "re-minting the same handle returns 200" \
  "$(status POST /agents/mint "$(cat <<JSON
{"brand":"cursor","repo_locale":"${REPO_LOCALE}","role":"orchestrator",
 "medium":"api","custody":"keychain"}
JSON
)")" "200"
check "a conflicting role returns 409" \
  "$(status POST /agents/mint "$(cat <<JSON
{"brand":"cursor","repo_locale":"${REPO_LOCALE}","role":"reviewer","medium":"api"}
JSON
)")" "409"

echo "-- delegate a worker"
worker="$(api POST /agents/mint "$(cat <<JSON
{"brand":"cursor","repo_locale":"${REPO_LOCALE}","role":"worker","medium":"api",
 "parent_agent_uuid":"${orchestrator_uuid}","custody":"keychain"}
JSON
)")"
check "worker handle is a child ordinal" "$(jq -r .logical_handle <<<"${worker}")" \
  "agent:cursor.${REPO_LOCALE}.0-0"
check "worker chain is three links" \
  "$(jq '.certificate_chain | length' <<<"${worker}")" "3"
check "worker was signed by the orchestrator" \
  "$(jq -r '.certificate.issuer.key_id' <<<"${worker}")" \
  "$(jq -r '.key_id' <<<"${orchestrator}")"
check "worker cannot mint" \
  "$(jq '.capabilities | index("agent.mint") == null' <<<"${worker}")" "true"
worker_uuid="$(jq -r .agent_uuid <<<"${worker}")"

echo "-- worker chain verifies"
check "chain verification" \
  "$(api POST /verify/certificate "$(jq -c '{certificate_chain: .certificate_chain}' \
    <<<"${worker}")" | jq -r .valid)" "true"

echo "-- ACP v2 registration"
registered="$(api POST /agents/register "$(cat <<JSON
{"brand":"cursor","repo_locale":"${REPO_LOCALE}-acp","ordinal_path":"0",
 "role":"orchestrator","medium":"web","session_id":"smoke-session"}
JSON
)")"
check "acp endpoint handle" "$(jq -r .endpoint_handle <<<"${registered}")" \
  "agent:cursor.${REPO_LOCALE}-acp.0@web"
check "acp response carries key material" \
  "$(jq -r '.keychain.public_key.crv' <<<"${registered}")" "Ed25519"
check "heartbeat" "$(api POST /agents/heartbeat "$(cat <<JSON
{"agent_uuid":"$(jq -r .agent_uuid <<<"${registered}")","medium":"web",
 "session_id":"smoke-session"}
JSON
)" | jq -r .success)" "true"

echo "-- capability token"
token_response="$(api POST /tokens/issue "$(cat <<JSON
{"agent_uuid":"${worker_uuid}","audience":"iac-bus","ttl_seconds":300,
 "capabilities":["bus.post","bus.read"]}
JSON
)")"
token="$(jq -r .token <<<"${token_response}")"
check "token is self-contained" "$(jq -r .self_contained <<<"${token_response}")" "true"
check "token verifies for iac-bus" \
  "$(api POST /tokens/verify "$(printf '{"token":"%s","audience":"iac-bus"}' "${token}")" \
    | jq -r .valid)" "true"
check "token grants bus.post" \
  "$(api POST /tokens/verify "$(printf \
    '{"token":"%s","required_capabilities":["bus.post"]}' "${token}")" | jq -r .valid)" \
  "true"
check "token does not grant agent.mint" \
  "$(api POST /tokens/verify "$(printf \
    '{"token":"%s","required_capabilities":["agent.mint"]}' "${token}")" | jq -r .valid)" \
  "false"
check "a token for another audience is refused" \
  "$(api POST /tokens/verify "$(printf '{"token":"%s","audience":"borgnet"}' "${token}")" \
    | jq -r .valid)" "false"

echo "-- revocation"
revoked="$(api POST "/agents/${orchestrator_uuid}/revoke" \
  '{"reason":"smoke test","cascade":true}')"
check "revocation cascades to the worker" "$(jq '.revoked | length' <<<"${revoked}")" "2"
check "the issued token stops verifying" \
  "$(api POST /tokens/verify "$(printf '{"token":"%s"}' "${token}")" | jq -r .valid)" \
  "false"
check "the revoked chain stops verifying" \
  "$(api POST /verify/certificate "$(jq -c '{certificate_chain: .certificate_chain}' \
    <<<"${worker}")" | jq -r .valid)" "false"
check "a revoked handle cannot be re-minted" \
  "$(status POST /agents/mint "$(cat <<JSON
{"brand":"cursor","repo_locale":"${REPO_LOCALE}","role":"orchestrator","medium":"api"}
JSON
)")" "409"

echo
echo "== ${pass} passed, ${fail} failed"
[[ "${fail}" -eq 0 ]]
