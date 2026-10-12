#!/usr/bin/env bash
#
# pingone-client-secret.sh
#
# Bash port of pingone-client-secret.js. Three related actions for PingOne
# "imported" OIDC applications and custom resources:
#
#   --action import        Create a new application or custom resource with a
#                           custom clientId, so it qualifies as "imported".
#                           This script never sends a clientSecret on import —
#                           PingOne always auto-generates one — use
#                           --action set-secret afterward to assign a custom value.
#   --action set-secret     (default) Set a custom clientSecret value on an
#                           app/resource that was already imported (created with
#                           a custom clientId via --action import).
#   --action rollback       Delete (roll back) a previously imported app/resource,
#                           e.g. to undo a test import or a failed migration wave.
#
# Each action can run once (via --type/--id/--client-id/--secret/--name flags)
# or in batch against a CSV file (via --csv). See "CSV batch mode" below.
#
# Background:
#   An application or custom resource becomes "imported" when it is created
#   via POST /applications or POST /resources with a custom `clientId` in the
#   request body. The `clientSecret` property is documented as optional on
#   that same import request, but this script deliberately never sends it —
#   every import lets PingOne auto-generate the secret. `--action set-secret`
#   then lets you go back and set that secret to a custom value once you have
#   it — e.g. once a secret recovered from the source system (PingFederate,
#   etc.) becomes available.
#
#   Set-secret applies ONLY to imported applications/resources — it cannot be
#   used to set a custom secret on an app/resource that was created normally
#   (without a custom clientId) via the admin console or a plain API create
#   call. PingOne returns an error in that case. `--action import` exists so
#   you have something import-eligible to test set-secret against.
#
#   Setting a custom clientId/clientSecret on import requires the environment
#   to have the underlying feature flags enabled (P14C-61681 for custom
#   clientId on import, P14C-68917 for the set-secret capability) — without
#   them, PingOne rejects the request. Contact your PingOne representative to
#   confirm these are enabled for the target environment before running
#   --action import or --action set-secret.
#
# Endpoints:
#   POST   /environments/{envId}/applications                         (import, Content-Type: application/json)
#   POST   /environments/{envId}/resources                            (import, Content-Type: application/json)
#   POST   /environments/{envId}/applications/{applicationId}/secret   (set-secret, Content-Type: application/vnd.pingidentity.secret+json)
#   POST   /environments/{envId}/resources/{resourceId}/secret        (set-secret, Content-Type: application/vnd.pingidentity.secret+json)
#   GET    /environments/{envId}/applications | /resources            (rollback/set-secret --csv: resolve id by clientId)
#   DELETE on /environments/{envId}/applications/{applicationId}      (rollback)
#   DELETE on /environments/{envId}/resources/{resourceId}            (rollback)
#
# Required PingOne worker-app permissions (granted via Environment Admin role):
#   applications:import:application  — for --action import   --type application
#   resources:import:resource        — for --action import   --type resource
#   applications:set:secret          — for --action set-secret --type application
#   resources:set:secret             — for --action set-secret --type resource
#   (standard read/delete application/resource permissions — for --action rollback,
#    and for resolving ids by clientId when using --csv)
#
# Requires: pingcli, jq
#
# Secret input:
#   For --action set-secret, the secret value is best supplied via the PINGONE_CLIENT_SECRET
#   environment variable rather than --secret, since command-line arguments are visible to
#   other local users via `ps`/`/proc` and get written to shell history. --secret still works
#   (for scripting contexts where an env var isn't practical) but PINGONE_CLIENT_SECRET takes
#   precedence when both are set, and a warning is printed if --secret is used at all.
#
# Usage:
#   # Import: create a single application or custom resource with a custom clientId
#   # (PingOne auto-generates the secret; follow up with --action set-secret for a custom value)
#   pingone-client-secret.sh \
#     --action         import \
#     --type           application | resource \
#     --env-id         <pingone-environment-uuid> \
#     [--profile       <pingcli-profile>]   (uses pingcli's default profile if omitted) \
#     [--client-id     <custom-client-id>] \
#     [--name          <display-name>] \
#     [--description   <description>] \
#     [--app-type      <WEB_APP|NATIVE_APP|SPA|WORKER|CUSTOM|...>] \
#     [--dry-run]
#
#   # Set-secret: assign a custom clientSecret to a single already-imported app/resource
#   PINGONE_CLIENT_SECRET=<custom-secret-value> pingone-client-secret.sh \
#     --type           application | resource \
#     --id             <applicationId-or-resourceId> \
#     --env-id         <pingone-environment-uuid> \
#     [--profile       <pingcli-profile>]   (uses pingcli's default profile if omitted) \
#     [--previous-expires-at <ISO-8601-timestamp>] \
#     [--dry-run]
#
#   # Rollback: delete a single previously imported app/resource
#   pingone-client-secret.sh \
#     --action         rollback \
#     --type           application | resource \
#     --id             <applicationId-or-resourceId> \
#     --env-id         <pingone-environment-uuid> \
#     [--profile       <pingcli-profile>]   (uses pingcli's default profile if omitted) \
#     [--dry-run]
#
#   # CSV batch mode — any action (import, set-secret, or rollback), looping over every row in a CSV file
#   pingone-client-secret.sh \
#     --action         import | set-secret | rollback \
#     --csv            <path-to.csv> \
#     --env-id         <pingone-environment-uuid> \
#     [--profile       <pingcli-profile>]   (uses pingcli's default profile if omitted) \
#     [--type          application | resource]   (optional filter — process only matching rows) \
#     [--dry-run]
#
# Examples:
#   # Import: create a WEB_APP application with a custom clientId (secret is auto-generated)
#   pingone-client-secret.sh \
#     --action        import \
#     --type          application \
#     --client-id     legacy-crm-app-001 \
#     --name          "Legacy CRM App" \
#     --app-type      WEB_APP \
#     --env-id        6b3de08f-caaa-4b4c-827a-bfd8b4d93d16 \
#     --profile       sandbox
#
#   # Import: create a CUSTOM resource with a custom clientId
#   pingone-client-secret.sh \
#     --action        import \
#     --type          resource \
#     --client-id     billing-api-resource-001 \
#     --name          "Billing API" \
#     --env-id        6b3de08f-caaa-4b4c-827a-bfd8b4d93d16 \
#     --profile       sandbox
#
#   # Set-secret: assign a custom clientSecret to an already-imported application (by its PingOne id)
#   PINGONE_CLIENT_SECRET=S3cr3t-Crm-App-001 pingone-client-secret.sh \
#     --action        set-secret \
#     --type          application \
#     --id            b1ad4ce0-f873-4807-9094-9d9b787e7d0f \
#     --env-id        6b3de08f-caaa-4b4c-827a-bfd8b4d93d16 \
#     --profile       sandbox
#
#   # Set-secret: assign a custom clientSecret and keep the old one valid for 30 more days
#   PINGONE_CLIENT_SECRET=S3cr3t-Billing-Res-001 pingone-client-secret.sh \
#     --action        set-secret \
#     --type          resource \
#     --id            65316d5c-8dc4-4c74-9251-4bff66c1973d \
#     --previous-expires-at 2026-08-07T00:00:00Z \
#     --env-id        6b3de08f-caaa-4b4c-827a-bfd8b4d93d16 \
#     --profile       sandbox
#
#   # Rollback: delete a previously imported application by its PingOne id
#   pingone-client-secret.sh \
#     --action        rollback \
#     --type          application \
#     --id            b1ad4ce0-f873-4807-9094-9d9b787e7d0f \
#     --env-id        6b3de08f-caaa-4b4c-827a-bfd8b4d93d16 \
#     --profile       sandbox
#
#   # CSV batch — import: create every row in migration-secrets/pf-secrets.csv (5 apps + 5 resources)
#   pingone-client-secret.sh \
#     --action        import \
#     --csv           migration-secrets/pf-secrets.csv \
#     --env-id        6b3de08f-caaa-4b4c-827a-bfd8b4d93d16 \
#     --profile       sandbox
#
#   # CSV batch — set-secret: set/rotate secrets for every row, resolving each id by its clientId
#   # (each row's clientSecret column supplies the secret — no PINGONE_CLIENT_SECRET needed)
#   pingone-client-secret.sh \
#     --action        set-secret \
#     --csv           migration-secrets/pf-secrets.csv \
#     --env-id        6b3de08f-caaa-4b4c-827a-bfd8b4d93d16 \
#     --profile       sandbox
#
#   # CSV batch — rollback: delete only the application rows, previewing first
#   pingone-client-secret.sh \
#     --action        rollback \
#     --csv           migration-secrets/pf-secrets.csv \
#     --type          application \
#     --env-id        6b3de08f-caaa-4b4c-827a-bfd8b4d93d16 \
#     --profile       sandbox \
#     --dry-run
#
# CSV batch mode:
#   Required columns: recordType, name, type, clientId, clientSecret
#     recordType   "application" or "resource"
#     name         Display name
#     type         PingOne app type (WEB_APP, NATIVE_APP, SPA, WORKER, ...) or resource
#                  type (CUSTOM) — passed through to --app-type per row
#     clientId     Custom clientId. For --action import, this is set on creation.
#                  For --action set-secret / rollback, this is used to look up the
#                  PingOne-generated id (there is no id column in the CSV).
#     clientSecret Custom secret. Used ONLY for --action set-secret (sets/rotates the
#                  secret). Ignored for --action import (PingOne always auto-generates
#                  the secret on import — see note above) and for --action rollback.
#   See migration-secrets/pf-secrets.csv for an example file.
#   Rows with an invalid recordType are skipped with a warning; unresolvable clientIds
#   (set-secret/rollback) are skipped with a warning. A per-row failure does not abort
#   the batch — a summary of succeeded/failed/skipped is printed at the end, and the
#   process exits 1 if any row failed.
#
# Options:
#   --action                 Optional. "set-secret" (default), "import", or "rollback".
#   --type                   Required unless --csv is used. "application" or "resource".
#                             With --csv, optional — filters the batch to matching rows.
#   --id                     Required for --action set-secret/rollback when not using --csv.
#                             The applicationId or resourceId (PingOne-generated `id`, not
#                             the custom clientId) of the imported app/resource.
#   --secret                 Required for --action set-secret unless PINGONE_CLIENT_SECRET is
#                             set (preferred — avoids the secret appearing in shell history or
#                             `ps` output). Custom secret value, 8-1024 characters. Not used by
#                             --action import — PingOne always auto-generates the secret on
#                             import; use --action set-secret afterward to assign a custom value.
#   --client-id               Optional, --action import only. Custom clientId, 8-256 characters,
#                             unique within the environment. If omitted, a sample value is
#                             generated so the created item still qualifies as "imported".
#   --name                   Optional, --action import only. Display name. Defaults to a
#                             generated sample name.
#   --description             Optional, --action import only. Defaults to a generic note that
#                             this is a sample created by this script.
#   --app-type                Optional, --action import only. PingOne application type
#                             (WEB_APP, NATIVE_APP, SPA, WORKER) or resource type (CUSTOM).
#                             Defaults to WEB_APP for applications, CUSTOM for resources.
#   --csv                    Path to a CSV file — see "CSV batch mode" above. When provided,
#                             --id/--client-id/--secret/--name/--description are ignored in
#                             favor of per-row CSV values (--secret/CSV clientSecret still
#                             only applies to --action set-secret, never --action import).
#   --env-id                 Required. PingOne environment UUID.
#   --profile                Optional. pingcli profile with worker-app credentials for that env.
#                             If omitted, pingcli's own configured default profile is used.
#   --previous-expires-at    Optional, --action set-secret only. ISO-8601 timestamp. If set, the
#                             app/resource's current secret is retained as a valid "previous"
#                             secret until this time (max 30 days out) instead of being
#                             invalidated immediately.
#   --dry-run                Print the request(s) that would be sent without sending them.
#                             In CSV mode with set-secret/rollback, id lookups still run live
#                             (read-only) so the preview reflects real resolved ids.
#
# Note: the exact request body schema for set-secret (a top-level `secret` property, with an
# optional `previous: { expiresAt }` object) is inferred from the sibling "Update Application
# Secret" (rotate) endpoint's documented `previous` behavior, which is expected to apply the
# same semantics here. The sample import payloads use minimal, reasonable defaults per
# app/resource type — verify field names against the current PingOne Platform API Reference
# before relying on this in production, in case anything changed before GA.

# This script relies on bash-only features (arrays, `local`, indirect
# expansion, etc.) and will not run correctly under a POSIX shell —
# including bash itself when invoked as `sh`/`/bin/sh`, which on macOS is
# bash running in POSIX-compatibility mode (BASH_VERSION is still set there,
# but several extensions are disabled) and on most Linux distros is dash or
# BusyBox ash (no BASH_VERSION at all). Fail fast with a clear message
# instead of hitting confusing syntax errors deeper in the script. This
# check is intentionally written in plain POSIX sh syntax (no [[ ]], no
# `local`) so it runs correctly under every shell it needs to detect, on
# macOS, Linux, and BusyBox-based containers alike.
if [ -z "${BASH_VERSION:-}" ]; then
  echo "ERROR: this script must be run with bash, not sh/dash/ash. Try: bash $0" >&2
  exit 1
fi
if shopt -q -o posix 2>/dev/null; then
  echo "ERROR: bash is running in POSIX mode (invoked as 'sh' or '/bin/sh'), which disables features this script needs. Try: bash $0" >&2
  exit 1
fi

set -euo pipefail

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

GREEN=$'\033[32m'; RED=$'\033[31m'; BLUE=$'\033[34m'; BOLD=$'\033[1m'; RESET=$'\033[0m'

# All progress/log output goes to stderr so it never pollutes the
# result-line protocol returned via command substitution (result=$(do_xxx ...)).
ok()      { echo "  ${GREEN}✔${RESET}  $1" >&2; }
fail()    { echo "  ${RED}✖${RESET}  $1" >&2; }
info()    { echo "  ${BLUE}→${RESET}  $1" >&2; }
section() { echo >&2; echo "${BOLD}$1${RESET}" >&2; }

print_help() {
  awk '/^#!/{next} /^# ?/{sub(/^# ?/,""); print; next} /^set -euo/{exit}' "$0"
}

# Omitting --profile lets pingcli fall back to its own configured default profile.
profile_label() {
  [ -n "$1" ] && echo "$1" || echo "(pingcli default)"
}

# ---------------------------------------------------------------------------
# type -> {path segment, import permission, set-secret permission} lookups
# (bash 3.2 compatible — no associative arrays)
# ---------------------------------------------------------------------------

path_segment_for_type() {
  case "$1" in
    application) echo "applications" ;;
    resource)    echo "resources" ;;
    *) echo ""; return 1 ;;
  esac
}

import_permission_for_type() {
  case "$1" in
    application) echo "applications:import:application" ;;
    resource)    echo "resources:import:resource" ;;
  esac
}

set_secret_permission_for_type() {
  case "$1" in
    application) echo "applications:set:secret" ;;
    resource)    echo "resources:set:secret" ;;
  esac
}

is_valid_type() {
  case "$1" in
    application|resource) return 0 ;;
    *) return 1 ;;
  esac
}

is_valid_record_type() {
  case "$1" in
    application|resource) return 0 ;;
    *) return 1 ;;
  esac
}

# ---------------------------------------------------------------------------
# pingcli invocation + API error extraction
# ---------------------------------------------------------------------------

# Runs pingcli with the given args. On success, prints stdout and returns 0.
# On failure, prints nothing to stdout; writes the raw output to the file
# named by $PINGCLI_ERR_FILE (if set) for the caller to inspect, and returns
# the underlying exit code.
run_pingcli() {
  local out
  if out=$(pingcli "$@" 2>&1); then
    printf '%s' "$out"
    return 0
  else
    local status=$?
    if [ -n "${PINGCLI_ERR_FILE:-}" ]; then
      printf '%s' "$out" > "$PINGCLI_ERR_FILE"
    fi
    return "$status"
  fi
}

# Extracts a human-readable summary from a pingcli JSON error body (stdin/arg).
# Falls back to the raw text if it isn't JSON.
summarize_api_error() {
  local raw="$1"
  local summary
  summary=$(printf '%s' "$raw" | jq -r '(.errors[0].message // .message // empty)' 2>/dev/null || true)
  if [ -z "$summary" ] || [ "$summary" = "null" ]; then
    summary="$raw"
  fi
  printf '%s' "$summary"
}

print_api_error_detail() {
  local raw="$1"
  if printf '%s' "$raw" | jq -e . >/dev/null 2>&1; then
    echo >&2
    echo "  ${BOLD}API error response:${RESET}" >&2
    printf '%s' "$raw" | jq '.' | sed 's/^/    /' >&2
  elif [ -n "$raw" ]; then
    echo >&2
    echo "  ${BOLD}API error response (raw):${RESET}" >&2
    printf '%s' "$raw" | sed 's/^/    /' >&2
  fi
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

ACTION="set-secret"
TYPE=""
ID=""
SECRET=""
ENV_ID=""
PROFILE=""
PREVIOUS_EXPIRES_AT=""
CLIENT_ID=""
NAME=""
DESCRIPTION=""
APP_TYPE=""
CSV=""
DRY_RUN=0

usage_and_exit() {
  echo "Usage:"
  echo "  Import:     create a new app/resource with a custom clientId (secret is auto-generated)"
  echo "    pingone-client-secret.sh --action import --type <application|resource> --env-id <uuid>"
  echo "      [--profile <profile>] [--client-id <id>] [--name <name>] [--description <text>] [--app-type <type>] [--dry-run]"
  echo "  Set secret: assign a custom clientSecret to an already-imported app/resource"
  echo "    PINGONE_CLIENT_SECRET=<value> pingone-client-secret.sh --type <application|resource> --id <id> --env-id <uuid>"
  echo "      [--profile <profile>] [--previous-expires-at <iso8601>] [--dry-run]"
  echo "  Rollback:   delete a previously imported app/resource"
  echo "    pingone-client-secret.sh --action rollback --type <application|resource> --id <id> --env-id <uuid> [--profile <profile>] [--dry-run]"
  echo "  CSV batch:  run import/set-secret/rollback for every row in a CSV file"
  echo "    pingone-client-secret.sh --action <import|set-secret|rollback> --csv <path.csv> --env-id <uuid>"
  echo "      [--profile <profile>] [--type <application|resource>] [--dry-run]"
  for e in "$@"; do echo "  - $e"; done
  exit 1
}

while [ $# -gt 0 ]; do
  case "$1" in
    --action)               ACTION="$2"; shift 2 ;;
    --type)                 TYPE="$2"; shift 2 ;;
    --id)                   ID="$2"; shift 2 ;;
    --secret)                SECRET="$2"; shift 2 ;;
    --client-id)             CLIENT_ID="$2"; shift 2 ;;
    --name)                  NAME="$2"; shift 2 ;;
    --description)           DESCRIPTION="$2"; shift 2 ;;
    --app-type)               APP_TYPE="$2"; shift 2 ;;
    --csv)                   CSV="$2"; shift 2 ;;
    --env-id)                ENV_ID="$2"; shift 2 ;;
    --profile)                PROFILE="$2"; shift 2 ;;
    --previous-expires-at)    PREVIOUS_EXPIRES_AT="$2"; shift 2 ;;
    --dry-run)                DRY_RUN=1; shift ;;
    --help|-h)                print_help; exit 0 ;;
    *) usage_and_exit "Unknown argument: $1" ;;
  esac
done

# PINGONE_CLIENT_SECRET takes precedence over --secret — command-line arguments are visible
# to other local users via `ps`/`/proc` and get written to shell history, so the env var is
# the preferred way to supply a secret. --secret still works for scripting contexts where an
# env var isn't practical, but using it prints a warning.
if [ -n "${PINGONE_CLIENT_SECRET:-}" ]; then
  if [ -n "$SECRET" ]; then
    info "Both --secret and PINGONE_CLIENT_SECRET are set — using PINGONE_CLIENT_SECRET."
  fi
  SECRET="$PINGONE_CLIENT_SECRET"
elif [ -n "$SECRET" ]; then
  info "--secret was passed on the command line — prefer the PINGONE_CLIENT_SECRET environment variable instead, since command-line arguments are visible to other local users via \`ps\`/\`/proc\` and get written to shell history."
fi

ERRORS=()
case "$ACTION" in
  set-secret|import|rollback) : ;;
  *) ERRORS+=('--action must be "set-secret", "import", or "rollback"') ;;
esac
[ -n "$ENV_ID" ] || ERRORS+=('--env-id is required')

if [ -n "$CSV" ]; then
  if [ -n "$TYPE" ] && ! is_valid_type "$TYPE"; then
    ERRORS+=('--type must be "application" or "resource" when provided with --csv')
  fi
  [ -f "$CSV" ] || ERRORS+=("--csv file not found: $CSV")
else
  if [ -z "$TYPE" ] || ! is_valid_type "$TYPE"; then
    ERRORS+=('--type must be "application" or "resource"')
  fi
  if [ "$ACTION" = "set-secret" ] || [ "$ACTION" = "rollback" ]; then
    [ -n "$ID" ] || ERRORS+=("--id is required for --action $ACTION")
  fi
  if [ "$ACTION" = "set-secret" ] && [ -z "$SECRET" ]; then
    ERRORS+=('--secret or PINGONE_CLIENT_SECRET is required for --action set-secret')
  fi
  if [ -n "$SECRET" ]; then
    len=${#SECRET}
    if [ "$len" -lt 8 ] || [ "$len" -gt 1024 ]; then
      ERRORS+=('--secret/PINGONE_CLIENT_SECRET must be between 8 and 1024 characters')
    fi
  fi
  if [ "$ACTION" = "import" ] && [ -n "$SECRET" ]; then
    info "--secret/PINGONE_CLIENT_SECRET is ignored for --action import — PingOne always auto-generates the secret on import. Use --action set-secret afterward to assign a custom value."
    SECRET=""
  fi
  if [ -n "$CLIENT_ID" ]; then
    len=${#CLIENT_ID}
    if [ "$len" -lt 8 ] || [ "$len" -gt 256 ]; then
      ERRORS+=('--client-id must be between 8 and 256 characters')
    fi
  fi
fi

if [ "${#ERRORS[@]}" -gt 0 ]; then
  usage_and_exit "${ERRORS[@]}"
fi

command -v jq >/dev/null 2>&1 || { fail "jq is required but not found on PATH"; exit 1; }
command -v pingcli >/dev/null 2>&1 || { fail "pingcli is required but not found on PATH"; exit 1; }

# ---------------------------------------------------------------------------
# Sample value generation (no clientId/name given for --action import)
# ---------------------------------------------------------------------------

sample_suffix() {
  printf '%s%s' "$$" "$(date +%s 2>/dev/null || echo 0)" | tail -c 12
}

# ---------------------------------------------------------------------------
# --action set-secret
# ---------------------------------------------------------------------------

# Builds the set-secret request body JSON on stdout.
build_secret_payload() {
  local secret="$1" previous_expires_at="$2"
  if [ -n "$previous_expires_at" ]; then
    jq -n --arg secret "$secret" --arg exp "$previous_expires_at" \
      '{secret: $secret, previous: {expiresAt: $exp}}'
  else
    jq -n --arg secret "$secret" '{secret: $secret}'
  fi
}

# do_set_secret <type> <id> <secret> <previousExpiresAt> <envId> <profile> <dryRun>
# Prints "OK <response-json>" or "FAIL <error-text>" on stdout; caller parses the prefix.
do_set_secret() {
  local type="$1" id="$2" secret="$3" previous_expires_at="$4" env_id="$5" profile="$6" dry_run="$7"
  local path_segment; path_segment=$(path_segment_for_type "$type")
  local api_path="environments/${env_id}/${path_segment}/${id}/secret"
  local payload; payload=$(build_secret_payload "$secret" "$previous_expires_at")

  if [ "$dry_run" = "1" ]; then
    info "[dry-run] POST $api_path"
    info "[dry-run] Content-Type: application/vnd.pingidentity.secret+json"
    info "[dry-run] Body: $(printf '%s' "$payload" | jq -c '.secret = "***redacted***"')"
    echo "DRYRUN"
    return 0
  fi

  local tmp_file; tmp_file=$(mktemp)
  printf '%s' "$payload" > "$tmp_file"

  local profile_args=(); [ -n "$profile" ] && profile_args=(--profile "$profile")
  local err_file; err_file=$(mktemp)
  local out status
  if out=$(PINGCLI_ERR_FILE="$err_file" run_pingcli \
      "${profile_args[@]+"${profile_args[@]}"}" --output-format json \
      pingone api --http-method POST --fail \
      --header 'Content-Type: application/vnd.pingidentity.secret+json' \
      --data "$tmp_file" "$api_path"); then
    status=0
  else
    status=$?
  fi
  rm -f "$tmp_file"

  if [ "$status" -eq 0 ]; then
    echo "OK $(printf '%s' "$out" | jq -c '.data // {}')"
  else
    local raw; raw=$(cat "$err_file")
    echo "FAIL $(summarize_api_error "$raw")"
    printf '%s' "$raw" > "${err_file}.detail"
    echo "ERRFILE ${err_file}.detail"
  fi
  rm -f "$err_file"
}

print_set_secret_common_causes() {
  local type="$1"
  echo >&2
  echo "  Common causes:" >&2
  echo "    - The ${type} was not imported with a custom clientId (this endpoint only works on imported $(path_segment_for_type "$type"))" >&2
  echo "    - The worker app is missing the $(set_secret_permission_for_type "$type") permission" >&2
  echo "    - The secret is outside the 8-1024 character range" >&2
  echo "    - The environment may not have the required feature flag enabled for set-secret (see Background above)" >&2
}

set_secret_single() {
  section "Set ${TYPE} secret"
  info "Target       : $(path_segment_for_type "$TYPE")/${ID}"
  info "Environment  : ${ENV_ID}"
  info "Profile      : $(profile_label "$PROFILE")"
  info "Permission   : $(set_secret_permission_for_type "$TYPE") (worker app must be granted this)"
  if [ -n "$PREVIOUS_EXPIRES_AT" ]; then
    info "Previous kept: until ${PREVIOUS_EXPIRES_AT}"
  else
    info "Previous kept: no — old secret invalidated immediately"
  fi

  local result; result=$(do_set_secret "$TYPE" "$ID" "$SECRET" "$PREVIOUS_EXPIRES_AT" "$ENV_ID" "$PROFILE" "$DRY_RUN")
  [ "$result" = "DRYRUN" ] && return 0

  local status="${result%% *}" rest="${result#* }"
  if [ "$status" = "OK" ]; then
    ok "Secret set on ${TYPE} ${ID}"
    info "Response: ${rest}"
  else
    fail "Failed to set secret: ${rest}"
    local err_line; err_line=$(printf '%s\n' "$result" | grep '^ERRFILE ' || true)
    if [ -n "$err_line" ]; then
      print_api_error_detail "$(cat "${err_line#ERRFILE }")"
      rm -f "${err_line#ERRFILE }"
    fi
    print_set_secret_common_causes "$TYPE"
    EXIT_CODE=1
  fi
}

# ---------------------------------------------------------------------------
# --action import
# ---------------------------------------------------------------------------

app_type_defaults_json() {
  # Emits the per-app-type default fields as a JSON object, given an app type.
  case "$1" in
    WEB_APP)
      jq -n '{grantTypes:["AUTHORIZATION_CODE"], responseTypes:["CODE"], tokenEndpointAuthMethod:"CLIENT_SECRET_BASIC", pkceEnforcement:"S256_REQUIRED", redirectUris:["https://example.com/callback"]}'
      ;;
    NATIVE_APP)
      jq -n '{grantTypes:["AUTHORIZATION_CODE"], responseTypes:["CODE"], tokenEndpointAuthMethod:"NONE", pkceEnforcement:"S256_REQUIRED", redirectUris:["com.example.app://callback"]}'
      ;;
    SPA)
      jq -n '{grantTypes:["AUTHORIZATION_CODE"], responseTypes:["CODE"], tokenEndpointAuthMethod:"NONE", pkceEnforcement:"S256_REQUIRED", redirectUris:["https://example.com/callback"]}'
      ;;
    WORKER)
      jq -n '{grantTypes:["CLIENT_CREDENTIALS"], tokenEndpointAuthMethod:"CLIENT_SECRET_BASIC"}'
      ;;
    *)
      echo ""; return 1 ;;
  esac
}

is_valid_app_type() {
  case "$1" in
    WEB_APP|NATIVE_APP|SPA|WORKER) return 0 ;;
    *) return 1 ;;
  esac
}

# build_import_payload <recordType> <appType> <clientId> <name> <description>
# Deliberately has no `secret`/`clientSecret` field — this script never sends a
# custom secret on import, even though `clientSecret` is documented as an
# optional import-request property. PingOne always auto-generates the
# secret; use --action set-secret afterward to assign a custom value.
build_import_payload() {
  local record_type="$1" app_type="$2" client_id="$3" name="$4" description="$5"
  local suffix; suffix=$(sample_suffix)

  [ -n "$client_id" ] || client_id="sample-imported-${record_type}-${suffix}"
  [ -n "$name" ] || name="Sample imported ${record_type} ${suffix}"
  [ -n "$description" ] || description="Sample ${record_type} created by pingone-client-secret.sh --action import"

  if [ "$record_type" = "application" ]; then
    is_valid_app_type "$app_type" || app_type="WEB_APP"
    local defaults; defaults=$(app_type_defaults_json "$app_type")
    jq -n --arg clientId "$client_id" --arg name "$name" --arg description "$description" \
          --arg type "$app_type" --argjson defaults "$defaults" \
      '{clientId: $clientId, name: $name, description: $description, enabled: false, protocol: "OPENID_CONNECT", type: $type} * $defaults'
  else
    # Custom resource — clientId/clientSecret import is only valid for type=CUSTOM.
    jq -n --arg clientId "$client_id" --arg name "$name" --arg description "$description" \
      '{clientId: $clientId, name: $name, description: $description, type: "CUSTOM", audience: $clientId, accessTokenValiditySeconds: 3600}'
  fi
}

# do_import <recordType> <appType> <clientId> <name> <description> <envId> <profile> <dryRun>
# Prints "OK <id> <clientId> <response-json>" or "FAIL <clientId> <error-text>" on stdout.
do_import() {
  local record_type="$1" app_type="$2" client_id="$3" name="$4" description="$5"
  local env_id="$6" profile="$7" dry_run="$8"
  local path_segment; path_segment=$(path_segment_for_type "$record_type")
  local api_path="environments/${env_id}/${path_segment}"
  local payload; payload=$(build_import_payload "$record_type" "$app_type" "$client_id" "$name" "$description")
  local effective_client_id; effective_client_id=$(printf '%s' "$payload" | jq -r '.clientId')

  if [ "$dry_run" = "1" ]; then
    info "[dry-run] POST $api_path"
    info "[dry-run] Content-Type: application/json"
    info "[dry-run] Body: $payload"
    echo "DRYRUN $effective_client_id"
    return 0
  fi

  local tmp_file; tmp_file=$(mktemp)
  printf '%s' "$payload" > "$tmp_file"

  local profile_args=(); [ -n "$profile" ] && profile_args=(--profile "$profile")
  local err_file; err_file=$(mktemp)
  local out status
  if out=$(PINGCLI_ERR_FILE="$err_file" run_pingcli \
      "${profile_args[@]+"${profile_args[@]}"}" --output-format json \
      pingone api --http-method POST --fail \
      --header 'Content-Type: application/json' \
      --data "$tmp_file" "$api_path"); then
    status=0
  else
    status=$?
  fi
  rm -f "$tmp_file"

  if [ "$status" -eq 0 ]; then
    local created_id created_client_id
    created_id=$(printf '%s' "$out" | jq -r '.data.id // empty')
    created_client_id=$(printf '%s' "$out" | jq -r '.data.clientId // empty')
    [ -n "$created_client_id" ] || created_client_id="$effective_client_id"
    echo "OK ${created_id} ${created_client_id}"
  else
    local raw; raw=$(cat "$err_file")
    echo "FAIL ${effective_client_id} $(summarize_api_error "$raw")"
    printf '%s' "$raw" > "${err_file}.detail"
    echo "ERRFILE ${err_file}.detail"
  fi
  rm -f "$err_file"
}

print_import_common_causes() {
  local type="$1" client_id="$2"
  echo >&2
  echo "  Common causes:" >&2
  echo "    - clientId \"${client_id}\" is already in use in this environment" >&2
  echo "    - The worker app is missing the $(import_permission_for_type "$type") permission" >&2
  echo "    - The environment may not have the required feature flag enabled for custom clientId on import (see Background above)" >&2
}

import_single() {
  section "Import ${TYPE}"
  info "Environment  : ${ENV_ID}"
  info "Profile      : $(profile_label "$PROFILE")"
  info "Permission   : $(import_permission_for_type "$TYPE") (worker app must be granted this)"
  info "clientSecret : (none sent — PingOne will auto-generate one)"

  local result; result=$(do_import "$TYPE" "$APP_TYPE" "$CLIENT_ID" "$NAME" "$DESCRIPTION" "$ENV_ID" "$PROFILE" "$DRY_RUN")
  local status="${result%% *}"
  [ "$status" = "DRYRUN" ] && return 0

  if [ "$status" = "OK" ]; then
    local rest="${result#* }"
    local id="${rest%% *}" client_id="${rest#* }"
    ok "Imported ${TYPE} created | id=${id} clientId=${client_id}"
    info "Use --action set-secret --id ${id} to assign a custom secret"
  else
    local rest="${result#* }"
    local client_id="${rest%% *}" summary="${rest#* }"
    fail "Failed to import ${TYPE}: ${summary}"
    local err_line; err_line=$(printf '%s\n' "$result" | grep '^ERRFILE ' || true)
    if [ -n "$err_line" ]; then
      print_api_error_detail "$(cat "${err_line#ERRFILE }")"
      rm -f "${err_line#ERRFILE }"
    fi
    print_import_common_causes "$TYPE" "$client_id"
    EXIT_CODE=1
  fi
}

# ---------------------------------------------------------------------------
# --action rollback
# ---------------------------------------------------------------------------

# do_rollback <type> <id> <envId> <profile> <dryRun>
# Prints "OK" or "FAIL <error-text>" on stdout.
do_rollback() {
  local type="$1" id="$2" env_id="$3" profile="$4" dry_run="$5"
  local path_segment; path_segment=$(path_segment_for_type "$type")
  local api_path="environments/${env_id}/${path_segment}/${id}"

  if [ "$dry_run" = "1" ]; then
    info "[dry-run] DELETE $api_path"
    echo "DRYRUN"
    return 0
  fi

  local profile_args=(); [ -n "$profile" ] && profile_args=(--profile "$profile")
  local err_file; err_file=$(mktemp)
  if run_pingcli "${profile_args[@]+"${profile_args[@]}"}" --output-format json \
      pingone api --http-method DELETE --fail "$api_path" >/dev/null 2> "$err_file"; then
    rm -f "$err_file"
    echo "OK"
  else
    local raw; raw=$(cat "$err_file")
    echo "FAIL $(summarize_api_error "$raw")"
    printf '%s' "$raw" > "${err_file}.detail"
    echo "ERRFILE ${err_file}.detail"
    rm -f "$err_file"
  fi
}

rollback_single() {
  section "Rollback ${TYPE}"
  info "Target       : $(path_segment_for_type "$TYPE")/${ID}"
  info "Environment  : ${ENV_ID}"
  info "Profile      : $(profile_label "$PROFILE")"

  local result; result=$(do_rollback "$TYPE" "$ID" "$ENV_ID" "$PROFILE" "$DRY_RUN")
  local status="${result%% *}"
  [ "$status" = "DRYRUN" ] && return 0

  if [ "$status" = "OK" ]; then
    ok "Deleted ${TYPE} ${ID}"
  else
    local summary="${result#* }"
    fail "Failed to delete ${TYPE} ${ID}: ${summary}"
    local err_line; err_line=$(printf '%s\n' "$result" | grep '^ERRFILE ' || true)
    if [ -n "$err_line" ]; then
      print_api_error_detail "$(cat "${err_line#ERRFILE }")"
      rm -f "${err_line#ERRFILE }"
    fi
    EXIT_CODE=1
  fi
}

# ---------------------------------------------------------------------------
# id resolution by clientId (used by CSV batch: set-secret / rollback)
# ---------------------------------------------------------------------------

# resolve_id_by_client_id <recordType> <clientId> <envId> <profile>
resolve_id_by_client_id() {
  local record_type="$1" client_id="$2" env_id="$3" profile="$4"
  local path_segment; path_segment=$(path_segment_for_type "$record_type")
  local profile_args=(); [ -n "$profile" ] && profile_args=(--profile "$profile")
  local out
  out=$(pingcli "${profile_args[@]+"${profile_args[@]}"}" --output-format json \
    pingone "$path_segment" list --environment-id "$env_id" \
    --query "data[?clientId=='${client_id}']" 2>/dev/null || echo '[]')
  printf '%s' "$out" | jq -r '.[0].id // empty'
}

# ---------------------------------------------------------------------------
# CSV parsing (RFC4180-ish: quoted fields, escaped quotes, embedded commas)
# ---------------------------------------------------------------------------

# Parses one CSV line from stdin into NUL-separated fields on stdout.
# Handles a single logical line only — multi-line quoted fields are not
# supported (matches this script's expected simple CSV shape).
csv_split_line() {
  local line="$1"
  local -a fields=()
  local field="" in_quotes=0
  local i len c next
  len=${#line}
  i=0
  while [ "$i" -lt "$len" ]; do
    c="${line:$i:1}"
    if [ "$in_quotes" = "1" ]; then
      if [ "$c" = '"' ]; then
        next="${line:$((i+1)):1}"
        if [ "$next" = '"' ]; then
          field="${field}\""
          i=$((i+2))
          continue
        else
          in_quotes=0
          i=$((i+1))
          continue
        fi
      else
        field="${field}${c}"
        i=$((i+1))
        continue
      fi
    fi
    if [ "$c" = '"' ]; then in_quotes=1; i=$((i+1)); continue; fi
    if [ "$c" = ',' ]; then fields+=("$field"); field=""; i=$((i+1)); continue; fi
    field="${field}${c}"
    i=$((i+1))
  done
  fields+=("$field")
  local out=""
  local f
  for f in "${fields[@]}"; do
    out="${out}${f}"$'\x1f'
  done
  printf '%s' "$out"
}

# ---------------------------------------------------------------------------
# CSV batch mode
# ---------------------------------------------------------------------------

run_csv_batch() {
  section "CSV batch — ${ACTION} ($CSV)"

  local header_line
  header_line=$(head -n 1 "$CSV" | tr -d '\r')
  local header_fields; header_fields=$(csv_split_line "$header_line")
  IFS=$'\x1f' read -r -a HEADER <<< "$header_fields"

  local idx_recordType=-1 idx_name=-1 idx_type=-1 idx_clientId=-1 idx_clientSecret=-1
  local i=0
  for h in "${HEADER[@]}"; do
    case "$h" in
      recordType)   idx_recordType=$i ;;
      name)         idx_name=$i ;;
      type)         idx_type=$i ;;
      clientId)     idx_clientId=$i ;;
      clientSecret) idx_clientSecret=$i ;;
    esac
    i=$((i+1))
  done

  local missing=""
  [ "$idx_recordType" -ge 0 ] || missing="${missing}recordType "
  [ "$idx_name" -ge 0 ] || missing="${missing}name "
  [ "$idx_type" -ge 0 ] || missing="${missing}type "
  [ "$idx_clientId" -ge 0 ] || missing="${missing}clientId "
  [ "$idx_clientSecret" -ge 0 ] || missing="${missing}clientSecret "
  if [ -n "$missing" ]; then
    fail "--csv file missing required column(s): ${missing}"
    exit 1
  fi

  local total=0 succeeded=0 skipped=0 failed=0 dryrun_count=0
  local failed_rows="" skipped_rows=""
  local row_num=1

  while IFS= read -r line || [ -n "$line" ]; do
    row_num=$((row_num+1))
    [ -z "$line" ] && continue
    line=$(printf '%s' "$line" | tr -d '\r')
    local fields_str; fields_str=$(csv_split_line "$line")
    IFS=$'\x1f' read -r -a F <<< "$fields_str"

    local rec_recordType="${F[$idx_recordType]:-}"
    local rec_name="${F[$idx_name]:-}"
    local rec_type="${F[$idx_type]:-}"
    local rec_clientId="${F[$idx_clientId]:-}"
    local rec_clientSecret="${F[$idx_clientSecret]:-}"

    if ! is_valid_record_type "$rec_recordType"; then
      info "[csv row ${row_num}] skipped — recordType \"${rec_recordType}\" must be \"application\" or \"resource\""
      continue
    fi
    if [ -n "$TYPE" ] && [ "$rec_recordType" != "$TYPE" ]; then
      continue
    fi

    total=$((total+1))
    local label="[row ${row_num}] ${rec_recordType} \"${rec_name}\" (clientId=${rec_clientId})"

    if [ "$ACTION" = "import" ]; then
      # rec_clientSecret is intentionally not passed through — this script never
      # sends a custom secret on import; PingOne always auto-generates one.
      local result; result=$(do_import "$rec_recordType" "$rec_type" "$rec_clientId" "$rec_name" "" "$ENV_ID" "$PROFILE" "$DRY_RUN")
      local status="${result%% *}"
      if [ "$status" = "DRYRUN" ]; then
        info "${label} — dry-run OK"
        dryrun_count=$((dryrun_count+1))
      elif [ "$status" = "OK" ]; then
        local rest="${result#* }"; local id="${rest%% *}"
        ok "${label} — imported id=${id}"
        succeeded=$((succeeded+1))
      else
        local rest="${result#* }"; local summary="${rest#* }"
        fail "${label} — ${summary}"
        local err_line; err_line=$(printf '%s\n' "$result" | grep '^ERRFILE ' || true)
        if [ -n "$err_line" ]; then
          print_api_error_detail "$(cat "${err_line#ERRFILE }")"
          rm -f "${err_line#ERRFILE }"
        fi
        failed=$((failed+1))
        failed_rows="${failed_rows}    – row ${row_num} (${rec_recordType} \"${rec_name}\", clientId=${rec_clientId}) — ${summary}\n"
      fi
      continue
    fi

    # set-secret and rollback both need the PingOne id resolved from clientId first.
    if [ -z "$rec_clientId" ]; then
      fail "${label} — skipped: no clientId in CSV row to resolve"
      skipped=$((skipped+1))
      skipped_rows="${skipped_rows}    – row ${row_num} (${rec_recordType} \"${rec_name}\", clientId=${rec_clientId}) — no clientId\n"
      continue
    fi

    local id; id=$(resolve_id_by_client_id "$rec_recordType" "$rec_clientId" "$ENV_ID" "$PROFILE")
    if [ -z "$id" ]; then
      fail "${label} — skipped: no ${rec_recordType} found with this clientId"
      skipped=$((skipped+1))
      skipped_rows="${skipped_rows}    – row ${row_num} (${rec_recordType} \"${rec_name}\", clientId=${rec_clientId}) — clientId not found\n"
      continue
    fi

    if [ "$ACTION" = "set-secret" ]; then
      if [ -z "$rec_clientSecret" ]; then
        fail "${label} — skipped: no clientSecret in CSV row"
        skipped=$((skipped+1))
        skipped_rows="${skipped_rows}    – row ${row_num} (${rec_recordType} \"${rec_name}\", clientId=${rec_clientId}) — no clientSecret\n"
        continue
      fi
      local result; result=$(do_set_secret "$rec_recordType" "$id" "$rec_clientSecret" "$PREVIOUS_EXPIRES_AT" "$ENV_ID" "$PROFILE" "$DRY_RUN")
      local status="${result%% *}"
      if [ "$status" = "DRYRUN" ]; then
        info "${label} — id=${id} — dry-run OK"
        dryrun_count=$((dryrun_count+1))
      elif [ "$status" = "OK" ]; then
        ok "${label} — id=${id} — secret set"
        succeeded=$((succeeded+1))
      else
        local rest="${result#* }"
        fail "${label} — id=${id} — ${rest}"
        local err_line; err_line=$(printf '%s\n' "$result" | grep '^ERRFILE ' || true)
        if [ -n "$err_line" ]; then
          print_api_error_detail "$(cat "${err_line#ERRFILE }")"
          rm -f "${err_line#ERRFILE }"
        fi
        failed=$((failed+1))
        failed_rows="${failed_rows}    – row ${row_num} (${rec_recordType} \"${rec_name}\", clientId=${rec_clientId}) — ${rest}\n"
      fi
    elif [ "$ACTION" = "rollback" ]; then
      local result; result=$(do_rollback "$rec_recordType" "$id" "$ENV_ID" "$PROFILE" "$DRY_RUN")
      local status="${result%% *}"
      if [ "$status" = "DRYRUN" ]; then
        info "${label} — id=${id} — dry-run OK"
        dryrun_count=$((dryrun_count+1))
      elif [ "$status" = "OK" ]; then
        ok "${label} — id=${id} — deleted"
        succeeded=$((succeeded+1))
      else
        local rest="${result#* }"
        fail "${label} — id=${id} — ${rest}"
        local err_line; err_line=$(printf '%s\n' "$result" | grep '^ERRFILE ' || true)
        if [ -n "$err_line" ]; then
          print_api_error_detail "$(cat "${err_line#ERRFILE }")"
          rm -f "${err_line#ERRFILE }"
        fi
        failed=$((failed+1))
        failed_rows="${failed_rows}    – row ${row_num} (${rec_recordType} \"${rec_name}\", clientId=${rec_clientId}) — ${rest}\n"
      fi
    fi
  done < <(tail -n +2 "$CSV")

  section "CSV batch summary"
  echo "  Total    : ${total}"
  echo "  Succeeded: ${succeeded}"
  [ "$dryrun_count" -gt 0 ] && echo "  Dry-run  : ${dryrun_count}"
  echo "  Skipped  : ${skipped}"
  echo "  Failed   : ${failed}"
  if [ "$failed" -gt 0 ]; then
    echo
    echo "  Failed rows:"
    printf '%b' "$failed_rows"
    EXIT_CODE=1
  fi
  if [ "$skipped" -gt 0 ]; then
    echo
    echo "  Skipped rows:"
    printf '%b' "$skipped_rows"
  fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

EXIT_CODE=0

if [ -n "$CSV" ]; then
  run_csv_batch
elif [ "$ACTION" = "import" ]; then
  import_single
elif [ "$ACTION" = "rollback" ]; then
  rollback_single
else
  set_secret_single
fi

exit "$EXIT_CODE"
