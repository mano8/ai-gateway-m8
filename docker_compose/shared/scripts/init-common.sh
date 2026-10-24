#!/usr/bin/env bash
# Shared stack initialiser (T87). Each stack's init.sh cd's into its own
# directory and calls this script; it needs only bash and Docker.
#
#   1. copies every *.env.example to its runtime name when that file is absent;
#   2. builds the gateway image from this repository (the stack's ai-migrate
#      service names the build);
#   3. runs shared/scripts/generate_material.py inside that image — no network,
#      read-only root, no capabilities, the host user's uid — to create every
#      missing file under ./secrets (mode 0600, never overwritten);
#   4. copies the derived, non-secret values (key ids) into the env files.
#
# Re-running is safe: nothing that exists is regenerated. AI_DEPLOYMENT_ID in
# particular is generated only when ./secrets/ai_deployment_id is absent and is
# never regenerated or rotated; back it up with the rest of ./secrets.
#
# Key rotation is not an init.sh operation: KEK and fingerprint-key rotation are
# gateway commands (README "Key rotation"); a regenerated key would orphan
# every stored credential.
set -Eeuo pipefail
IFS=$'\n\t'

COMMON_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STACK_VAULT=0
# The local tag every stack builds for its three gateway services.
IMAGE="ai-gateway-m8:stack"

for arg in "$@"; do
    case "$arg" in
        --vault) STACK_VAULT=1 ;;
        -h|--help)
            echo "Usage: init.sh"
            echo "  Creates missing env files and ./secrets; never overwrites either."
            exit 0 ;;
        *) echo "Usage: init.sh (unknown argument: ${arg})" >&2; exit 1 ;;
    esac
done

command -v docker >/dev/null || { echo "ERROR: docker is required" >&2; exit 1; }
docker compose version >/dev/null 2>&1 || { echo "ERROR: docker compose v2 is required" >&2; exit 1; }

echo "==> ai-gateway-m8 stack init: $(basename "$(pwd)")"

# --- env files from their templates (never overwritten) ---
shopt -s nullglob dotglob
for tmpl in *.env.example; do
    target="${tmpl%.example}"
    if [[ ! -f "$target" ]]; then
        cp "$tmpl" "$target"
        echo "    created ${target} from ${tmpl}"
    fi
    chmod 600 "$target"
done
shopt -u nullglob dotglob

# --- secrets directory ---
mkdir -p secrets
chmod 700 secrets

# --- the gateway image (built from this repository, never pulled) ---
echo "==> building the gateway image"
docker compose build ai-migrate
docker image inspect "$IMAGE" >/dev/null || { echo "ERROR: ${IMAGE} was not built" >&2; exit 1; }

# --- secret material (generated inside the image; nothing printed) ---
# The generator runs as the directory's owner: the host user on the first run,
# uid 1000 once a stack start has handed the files to their readers.
OWNER="$(ls -nd secrets | awk '{print $3 ":" $4}')"
# Traefik's certificate names the stack's DOMAIN (gateway.env) and localhost.
STACK_DOMAIN="$(awk -F= '$1 == "DOMAIN" { print $2 }' gateway.env)"
echo "==> generating missing secret material in ./secrets"
docker run --rm -i \
    --network none \
    --read-only \
    --cap-drop ALL \
    --security-opt no-new-privileges:true \
    --user "$OWNER" \
    --env "STACK_VAULT=${STACK_VAULT}" \
    --env "STACK_DOMAIN=${STACK_DOMAIN}" \
    --volume "$(pwd)/secrets:/out" \
    --entrypoint python \
    "$IMAGE" - < "${COMMON_DIR}/generate_material.py"

[[ -f secrets/derived.env ]] || { echo "ERROR: generation wrote no secrets/derived.env" >&2; exit 1; }

# Write KEY=VALUE into an env file, replacing an existing (commented or not)
# line or appending. Temp file plus mv: no sed -i (differs on macOS and GNU).
set_env_var() {
    local file="$1" key="$2" value="$3" tmp
    tmp="$(mktemp)"
    if grep -qE "^#? *${key}=" "$file"; then
        sed "s|^#\? *${key}=.*|${key}=${value}|" "$file" > "$tmp"
    else
        cat "$file" > "$tmp"
        printf '%s=%s\n' "$key" "$value" >> "$tmp"
    fi
    mv "$tmp" "$file"
    chmod 600 "$file"
}

derived() {
    awk -F= -v key="$1" '$1 == key { print substr($0, length(key) + 2) }' secrets/derived.env
}

set_env_var gateway.env AI_EXECUTION_RECEIPT_KID "$(derived AI_EXECUTION_RECEIPT_KID)"
set_env_var auth.env ACCESS_KEY_ID "$(derived ACCESS_KEY_ID)"
# Single-quoted: compose reads a single-quoted env_file value literally, so the
# digest's '$' separators are never interpolated.
set_env_var auth.env PRIVATE_API_CONSUMERS "'$(derived PRIVATE_API_CONSUMERS)'"
echo "    bound AI_EXECUTION_RECEIPT_KID (gateway.env), ACCESS_KEY_ID and"
echo "    PRIVATE_API_CONSUMERS (auth.env: the gateway's row, a salted digest)"
echo "    the suite's test issuer: kid $(derived TEST_ISSUER_KID), seed ./secrets/test_issuer_seed"

# Every runtime env file must be free of placeholders before compose up.
leftover="$(grep -l 'changethis' ./*.env 2>/dev/null || true)"
if [[ -n "$leftover" ]]; then
    echo ""
    echo "NOTE: replace every 'changethis' before 'docker compose up' in:"
    echo "$leftover" | sed 's/^/        /'
fi

echo "==> done. Back up ./secrets (it holds AI_DEPLOYMENT_ID and the KEK)."
echo "    Start: docker compose up -d"
