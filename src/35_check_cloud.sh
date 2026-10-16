# ------------------------------------------------------------------------------
# Check: cloud credentials and workload identity metadata (never reads secrets)
# ------------------------------------------------------------------------------

run_check_cloud() {
    section "Cloud Identity and Configuration"

    local env_names='' name present=0
    for name in AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_PROFILE \
                AWS_WEB_IDENTITY_TOKEN_FILE AWS_ROLE_ARN AWS_CONTAINER_CREDENTIALS_RELATIVE_URI \
                AWS_CONTAINER_CREDENTIALS_FULL_URI AZURE_CLIENT_ID AZURE_TENANT_ID \
                AZURE_CLIENT_SECRET AZURE_FEDERATED_TOKEN_FILE GOOGLE_APPLICATION_CREDENTIALS \
                CLOUDSDK_CONFIG GOOGLE_CLOUD_PROJECT GCP_PROJECT ARM_CLIENT_ID ARM_CLIENT_SECRET \
                ARM_TENANT_ID KUBECONFIG; do
        if printenv "$name" >/dev/null 2>&1; then
            env_names="${env_names}${name}, "
            present=1
        fi
    done
    if [ "$present" -eq 1 ]; then
        finding "INFO" "cloud.identity_env_names" "Cloud/workload identity environment variables are present" \
            "Names only: ${env_names%, }. Values are deliberately not collected or printed. Presence alone does not establish access or exposure."
    else
        finding "OK" "cloud.no_identity_env_names" "No common cloud identity environment variable names found" \
            "This does not rule out instance metadata identities, credential files, SDK defaults, or other provider-specific mechanisms."
    fi

    local homes='' home_dir path count=0 shown=0 candidates=''
    if [ -n "${HOME:-}" ] && [ -d "$HOME" ]; then homes="$HOME"; fi
    if [ -r /etc/passwd ]; then
        while IFS=: read -r _ _ uid _ _ h _; do
            case "$uid:$h" in
                [0-9]*:/*) [ -d "$h" ] && homes="${homes}${homes:+$'\n'}$h" ;;
            esac
        done < /etc/passwd
    fi

    # Inspect path metadata only; never cat, source, parse, or upload credential files.
    while IFS= read -r home_dir; do
        [ -n "$home_dir" ] || continue
        for path in \
            "$home_dir/.aws/credentials" "$home_dir/.aws/config" \
            "$home_dir/.azure/accessTokens.json" "$home_dir/.azure/azureProfile.json" \
            "$home_dir/.config/gcloud/application_default_credentials.json" \
            "$home_dir/.config/gcloud/credentials.db" "$home_dir/.kube/config" \
            "$home_dir/.docker/config.json" "$home_dir/.config/containers/auth.json" \
            "$home_dir/.terraform.d/credentials.tfrc.json" "$home_dir/.config/gh/hosts.yml"; do
            [ -f "$path" ] || continue
            count=$((count + 1))
            local mode owner last_digit
            mode="$(stat -Lc '%a' "$path" 2>/dev/null || stat -f '%Lp' "$path" 2>/dev/null)"
            owner="$(stat -Lc '%U' "$path" 2>/dev/null || stat -f '%Su' "$path" 2>/dev/null)"
            [ -n "$mode" ] || mode='unknown'
            [ -n "$owner" ] || owner='unknown'
            if [ "$shown" -lt 100 ]; then
                candidates="${candidates}${path} (owner=${owner}, mode=${mode})"$'\n'
                shown=$((shown + 1))
            fi
            # Flag only clearly world-readable sensitive files; do not infer that
            # a file is vulnerable merely because the current account can read it.
            case "$mode" in
                *[0-7])
                    last_digit="${mode: -1}"
                    if [ "$last_digit" != 'unknown' ] && [ $((10#$last_digit & 4)) -ne 0 ]; then
                        case "$path" in
                            */.aws/config|*/.azure/azureProfile.json)
                                # These files may contain account/profile metadata but are not
                                # inherently credential-bearing; report the path as INFO only.
                                ;;
                            *)
                                finding "HIGH" "cloud.world_readable_config" "Cloud/deployment credential configuration is world-readable: $path" \
                                    "Metadata only. Confirm the file contains sensitive material and inspect the provider's identity/credential scope; Escal8 did not read its contents."
                                ;;
                        esac
                    fi
                    ;;
            esac
        done
    done <<EOF_HOMES
$(printf '%s\n' "$homes" | sort -u)
EOF_HOMES

    if [ "$shown" -gt 0 ]; then
        finding "INFO" "cloud.config_paths" "Cloud and deployment configuration paths found ($shown shown)" \
            "$candidates"
        [ "$count" -le 100 ] || finding "INFO" "cloud.config_paths_truncated" "Cloud configuration path listing truncated" "More than 100 paths matched. No file contents were read."
    else
        finding "OK" "cloud.config_paths_none" "No common cloud configuration paths found in enumerated home directories" \
            "Path list is intentionally bounded and does not cover every SDK, container, or workload identity location."
    fi
    return 0
}
