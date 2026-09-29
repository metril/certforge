#!/bin/sh
# Vault e2e fixture (Task 14): enables and configures everything the compose
# stack's second boot (deploy/compose.vault.yaml) and TestVaultAgainstCompose
# need against the dev-mode Vault started by this same compose file --
# transit for the KEK, pki for the vaultpki CA, secret/ (kv-v2, dev default)
# for vault-kv, and an AppRole the server logs in with. Runs once per stack
# (VAULT_ADDR/VAULT_TOKEN come from the vault-init service's own
# environment); every "enable" step tolerates already being enabled so a
# manual rerun against a stack that was not torn down does not fail.
set -eu

echo "vault-init: waiting for $VAULT_ADDR"
i=0
until vault status >/dev/null 2>&1; do
	i=$((i + 1))
	if [ "$i" -ge 30 ]; then
		echo "vault-init: vault not reachable after 30s" >&2
		exit 1
	fi
	sleep 1
done

echo "vault-init: transit"
vault secrets enable transit 2>/dev/null || true
vault write -f transit/keys/certforge >/dev/null

echo "vault-init: pki"
vault secrets enable -path=pki -max-lease-ttl=87600h pki 2>/dev/null || true
vault write -field=certificate pki/root/generate/internal \
	common_name="CertForge E2E Root" ttl=87600h >/dev/null
vault write pki/roles/certforge \
	allow_any_name=true allow_ip_sans=true enforce_hostnames=false max_ttl=720h key_type=any >/dev/null

echo "vault-init: secret/ (kv-v2, dev default) — verify"
vault kv put secret/certforge-e2e-vault-init-probe probe=1 >/dev/null
vault kv get -field=probe secret/certforge-e2e-vault-init-probe | grep -qx 1
vault kv metadata delete secret/certforge-e2e-vault-init-probe >/dev/null

echo "vault-init: approle"
vault auth enable approle 2>/dev/null || true
cat >/tmp/certforge-e2e.hcl <<'EOF'
path "transit/encrypt/certforge" { capabilities = ["update"] }
path "transit/decrypt/certforge" { capabilities = ["update"] }
path "transit/rewrap/certforge"  { capabilities = ["update"] }
path "transit/keys/certforge"    { capabilities = ["read"] }
path "pki/sign/certforge"        { capabilities = ["update"] }
path "pki/revoke"                { capabilities = ["update"] }
path "pki/cert/ca"               { capabilities = ["read"] }
path "secret/data/*"             { capabilities = ["create", "read", "update", "delete"] }
path "secret/metadata/*"         { capabilities = ["list", "read", "delete"] }
EOF
vault policy write certforge-e2e /tmp/certforge-e2e.hcl >/dev/null
vault write auth/approle/role/certforge \
	token_policies="certforge-e2e" token_ttl=1h token_max_ttl=4h \
	secret_id_ttl=0 token_num_uses=0 >/dev/null

# Fixed role_id/secret_id (planner check: the custom-secret-id endpoint lets
# the secret_id be set explicitly instead of Vault generating a random one)
# so every rerun of this script against a fresh Vault yields the same
# credentials, and the second compose boot's CF_KEK_VAULT_SECRET_ID_FILE
# never needs to be re-read after the fact — the secret_id is simply the
# root token this script itself authenticates with.
ROLE_ID=$(vault read -field=role_id auth/approle/role/certforge/role-id)
SECRET_ID=$(vault write -field=secret_id auth/approle/role/certforge/custom-secret-id \
	secret_id="$VAULT_TOKEN")

mkdir -p /e2e-vault
printf '%s' "$ROLE_ID" >/e2e-vault/role_id
printf '%s' "$SECRET_ID" >/e2e-vault/secret_id
echo "vault-init: wrote /e2e-vault/{role_id,secret_id}"
