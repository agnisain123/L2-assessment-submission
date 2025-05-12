#!/bin/bash

LOG_FILE="../problems/nginx_access.log"

# Function to extract version and check if it's old
is_old_version() {
    browser_version=$1
    browser_name=$2
    major_version=$(echo "$browser_version" | cut -d'.' -f1)

    case "$browser_name" in
        "Chrome")  [ "$major_version" -le 58 ] && return 0 ;;
        "Firefox") [ "$major_version" -le 55 ] && return 0 ;;
        "Edge")    [ "$major_version" -le 15 ] && return 0 ;;
        "Safari")  [ "$major_version" -le 9 ]  && return 0 ;;
    esac

    return 1
}

echo "[+] Parsing Log File: $LOG_FILE"

# 1. High error rate IPs (4xx/5xx)
echo -e "\n[!] IPs with High Error Rate (4xx/5xx > 50%)"
awk '
{
    ip=$1
    status=$10
    if (status ~ /^[45]/) {
        errors[ip]++
    }
    total_requests[ip]++
} 
END {
    for (ip in total_requests) {
        if (total_requests[ip] > 100) {
            error_rate = errors[ip] / total_requests[ip] * 100
            if (error_rate >= 50) {
                print ip, "(" error_rate "%)"
            }
        }
    }
}
' "$LOG_FILE" | sort -nr -k2,2 | head -20

# 2. Aggressive IPs (over 1000 requests)
echo -e "\n[!] Aggressive IPs (over 1000 requests)"
awk '{print $1}' "$LOG_FILE" | sort | uniq -c | sort -nr | awk '$1 > 1000 {print $0}' | head -20

# 3. Suspicious paths
echo -e "\n[!] Suspicious Paths"
grep -Ei '(/wp-login|/admin|/phpmyadmin|/etc/passwd|/proc/self|/\.env|/config.php|/\.git|/xmlrpc.php)' "$LOG_FILE" | cut -d'"' -f2 | sort | uniq -c | sort -nr | head -20

# 4. Potential SQL injection
echo -e "\n[!] Potential SQL Command Injection"
grep -Ei "(select|insert|drop|--|union|eval|system\(|\.\./)" "$LOG_FILE" | cut -d'"' -f2 | sort | uniq -c | sort -nr | head -10

# 5. Malicious user agents
echo -e "\n[!] Suspicious User Agents"
declare -A user_agent_count
while read -r line; do
    user_agent=$(echo "$line" | cut -d'"' -f8)

    # Check for Chrome, Firefox, Edge, Safari
    for browser in "Chrome" "Firefox" "Edge" "Safari"; do
        if [[ "$user_agent" =~ $browser/([0-9]+)\. ]]; then
            browser_version="${BASH_REMATCH[1]}"
            
            # Check if the version is old
            if is_old_version "$browser_version" "$browser"; then
                key="$browser $browser_version"
                ((user_agent_count["$key"]++))
            fi
            break
        fi
    done
done < <(grep -Ei 'Chrome/|Firefox/|Edge/|Safari/' "$LOG_FILE")
for key in "${!user_agent_count[@]}"; do
    echo "$key: ${user_agent_count[$key]}"
done

# 6. IPs Accessing Many Unique URLs
echo -e "\n[!] IPs Accessing Many Unique URLs"
awk '{print $1,$7}' "$LOG_FILE" | sort | uniq | awk '{count[$1]++} END {for (ip in count) if (count[ip]>100) print ip, count[ip]}' | sort -nr | head -20