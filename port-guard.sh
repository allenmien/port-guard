#!/bin/sh

# Port Guard: per-port source whitelist manager for iptables/ipset.
# Compatible target shells: Debian/Ubuntu dash, Alpine BusyBox ash.

VERSION="0.1.0"

PREFIX="${PORT_GUARD_PREFIX:-/usr/local}"
BIN_PATH="${PORT_GUARD_BIN:-$PREFIX/sbin/port-guard}"
BASE_DIR="${PORT_GUARD_BASE:-/etc/port-guard}"
CONFIG_DIR="$BASE_DIR/rules"
STATE_DIR="${PORT_GUARD_STATE:-/var/lib/port-guard}"
RUN_DIR="${PORT_GUARD_RUN:-/run/port-guard}"
MAXELEM="${PORT_GUARD_MAXELEM:-131072}"
QUIET=0

for _arg in "$@"; do
    if [ "$_arg" = "--quiet" ] || [ "$_arg" = "-q" ]; then
        QUIET=1
    fi
done

log() {
    [ "$QUIET" -eq 1 ] && return 0
    printf '%s\n' "$*"
}

warn() {
    [ "$QUIET" -eq 1 ] && return 0
    printf 'WARN: %s\n' "$*" >&2
}

die() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

need_root() {
    [ "$(id -u)" = "0" ] || die "请用 root 运行：sudo $0 $*"
}

mkdirs() {
    mkdir -p "$CONFIG_DIR" "$STATE_DIR" "$RUN_DIR"
}

acquire_update_lock() {
    mkdirs
    _lock="$RUN_DIR/update.lock"
    if mkdir "$_lock" 2>/dev/null; then
        printf '%s\n' "$$" >"$_lock/pid" 2>/dev/null || true
        trap 'release_update_lock' EXIT
        trap 'release_update_lock; exit 130' INT TERM
        return 0
    fi
    warn "已有更新任务正在运行，跳过本次 update"
    exit 0
}

release_update_lock() {
    rm -f "$RUN_DIR/update.lock/pid" 2>/dev/null || true
    rmdir "$RUN_DIR/update.lock" 2>/dev/null || true
    trap - EXIT INT TERM
}

upper() {
    printf '%s' "$1" | tr 'abcdefghijklmnopqrstuvwxyz' 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
}

lower() {
    printf '%s' "$1" | tr 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' 'abcdefghijklmnopqrstuvwxyz'
}

trim_list() {
    printf '%s' "$*" | tr ',\t\r\n' '    ' | awk '{$1=$1; print}'
}

shell_quote() {
    printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"
}

is_uint() {
    case "$1" in
        ''|*[!0-9]*) return 1 ;;
        *) return 0 ;;
    esac
}

validate_port() {
    is_uint "$1" || die "端口必须是 1-65535 的数字"
    [ "$1" -ge 1 ] 2>/dev/null && [ "$1" -le 65535 ] 2>/dev/null || die "端口必须是 1-65535"
}

validate_proto() {
    case "$(lower "$1")" in
        tcp|udp|both) return 0 ;;
        *) die "协议只能是 tcp、udp 或 both" ;;
    esac
}

validate_action() {
    case "$(upper "$1")" in
        DROP|REJECT) return 0 ;;
        *) die "动作只能是 DROP 或 REJECT" ;;
    esac
}

key_for() {
    printf '%s_%s' "$(lower "$1")" "$2"
}

chain_name() {
    printf 'PG_%s_%s' "$(upper "$1")" "$2"
}

set4_name() {
    printf 'pg_%s_%s_v4' "$(lower "$1")" "$2"
}

set6_name() {
    printf 'pg_%s_%s_v6' "$(lower "$1")" "$2"
}

conf_path() {
    printf '%s/%s.conf' "$CONFIG_DIR" "$(key_for "$1" "$2")"
}

state_path() {
    printf '%s/%s.%s' "$STATE_DIR" "$(key_for "$1" "$2")" "$3"
}

safe_cache_key() {
    printf '%s' "$1" | cksum | awk '{print $1}'
}

source_cache_path() {
    _kind="$1"
    _value="$2"
    printf '%s/cache_%s_%s.txt' "$STATE_DIR" "$_kind" "$(safe_cache_key "$_value")"
}

self_path() {
    case "$0" in
        */*) _dir=$(dirname "$0"); _base=$(basename "$0"); (cd "$_dir" 2>/dev/null && printf '%s/%s\n' "$(pwd -P)" "$_base") ;;
        *) command -v "$0" ;;
    esac
}

extract_ip_tokens() {
    sed 's/#.*$//; s/[;,]/ /g; s/\r//g' | awk '
        {
            for (i = 1; i <= NF; i++) {
                t = $i
                gsub(/^[^0-9A-Fa-f:.]+/, "", t)
                gsub(/[^0-9A-Fa-f:.\/]+$/, "", t)
                if (t ~ /^[0-9.]+(\/[0-9]+)?$/ || t ~ /^[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]+(\/[0-9]+)?$/) {
                    print t
                }
            }
        }
    '
}

split_ip_versions() {
    _input="$1"
    _v4="$2"
    _v6="$3"
    : >"$_v4"
    : >"$_v6"
    while IFS= read -r _ip; do
        [ -n "$_ip" ] || continue
        case "$_ip" in
            *:*) printf '%s\n' "$_ip" >>"$_v6" ;;
            *) printf '%s\n' "$_ip" >>"$_v4" ;;
        esac
    done <"$_input"
}

download_url() {
    _url="$1"
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL --connect-timeout 10 --max-time 45 "$_url"
        return $?
    fi
    if command -v wget >/dev/null 2>&1; then
        wget -q -O - "$_url"
        return $?
    fi
    if command -v fetch >/dev/null 2>&1; then
        fetch -q -o - "$_url"
        return $?
    fi
    return 127
}

resolve_domain() {
    _domain="$1"
    _tmp="$2"
    : >"$_tmp"

    if command -v getent >/dev/null 2>&1; then
        getent ahosts "$_domain" 2>/dev/null | awk '{print $1}' >>"$_tmp"
    fi

    if command -v dig >/dev/null 2>&1; then
        dig +short A "$_domain" 2>/dev/null >>"$_tmp"
        dig +short AAAA "$_domain" 2>/dev/null >>"$_tmp"
    fi

    if command -v host >/dev/null 2>&1; then
        host "$_domain" 2>/dev/null | awk '/has address/ {print $4} /has IPv6 address/ {print $5}' >>"$_tmp"
    fi

    if command -v nslookup >/dev/null 2>&1; then
        nslookup "$_domain" 2>/dev/null | awk '
            /^Name:/ { answer = 1; next }
            answer && /^Address[[:space:]]*[0-9]*:/ {
                for (i = 2; i <= NF; i++) print $i
            }
        ' | extract_ip_tokens >>"$_tmp"
    fi

    sort -u "$_tmp" | extract_ip_tokens >"$_tmp.sorted"
    mv "$_tmp.sorted" "$_tmp"
    [ -s "$_tmp" ]
}

load_config() {
    _proto="$1"
    _port="$2"
    _conf=$(conf_path "$_proto" "$_port")
    [ -f "$_conf" ] || die "没有找到规则配置：$_proto/$_port"

    PORT=''
    PROTO=''
    ACTION='DROP'
    INTERVAL_MINUTES='30'
    SOURCES_IPS=''
    SOURCES_FILES=''
    SOURCES_URLS=''
    SOURCES_DOMAINS=''

    # shellcheck disable=SC1090
    . "$_conf"

    validate_port "$PORT"
    validate_proto "$PROTO"
    validate_action "$ACTION"
    is_uint "$INTERVAL_MINUTES" || die "$_conf 里的 INTERVAL_MINUTES 必须是数字"
    [ "$INTERVAL_MINUTES" -ge 1 ] 2>/dev/null || die "$_conf 里的 INTERVAL_MINUTES 必须 >= 1"
}

write_config_one() {
    _proto="$(lower "$1")"
    _port="$2"
    _action="$(upper "$3")"
    _interval="$4"
    _ips="$(trim_list "$5")"
    _files="$(trim_list "$6")"
    _urls="$(trim_list "$7")"
    _domains="$(trim_list "$8")"

    validate_port "$_port"
    validate_proto "$_proto"
    validate_action "$_action"
    is_uint "$_interval" || die "更新时间间隔必须是分钟数字"
    [ "$_interval" -ge 1 ] 2>/dev/null || die "更新时间间隔必须 >= 1"

    mkdirs
    _conf=$(conf_path "$_proto" "$_port")
    {
        printf '# Managed by port-guard. Edit carefully or use port-guard add.\n'
        printf 'PORT=%s\n' "$(shell_quote "$_port")"
        printf 'PROTO=%s\n' "$(shell_quote "$_proto")"
        printf 'ACTION=%s\n' "$(shell_quote "$_action")"
        printf 'INTERVAL_MINUTES=%s\n' "$(shell_quote "$_interval")"
        printf 'SOURCES_IPS=%s\n' "$(shell_quote "$_ips")"
        printf 'SOURCES_FILES=%s\n' "$(shell_quote "$_files")"
        printf 'SOURCES_URLS=%s\n' "$(shell_quote "$_urls")"
        printf 'SOURCES_DOMAINS=%s\n' "$(shell_quote "$_domains")"
    } >"$_conf"
    chmod 600 "$_conf" 2>/dev/null || true
    log "已写入配置：$_conf"
}

refresh_one() {
    _proto="$1"
    _port="$2"
    load_config "$_proto" "$_port"
    mkdirs

    _tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/port-guard.XXXXXX") || die "无法创建临时目录"
    _all="$_tmpdir/all.txt"
    _raw="$_tmpdir/raw.txt"
    : >"$_all"

    for _ip in $SOURCES_IPS; do
        printf '%s\n' "$_ip"
    done | extract_ip_tokens >>"$_all"

    for _file in $SOURCES_FILES; do
        if [ -r "$_file" ]; then
            extract_ip_tokens <"$_file" >>"$_all"
        else
            warn "无法读取本地 IP 文件：$_file"
        fi
    done

    for _url in $SOURCES_URLS; do
        _cache=$(source_cache_path "url" "$_url")
        if download_url "$_url" >"$_raw"; then
            extract_ip_tokens <"$_raw" | sort -u >"$_cache"
            cat "$_cache" >>"$_all"
            log "URL 已更新：$_url"
        elif [ -s "$_cache" ]; then
            warn "URL 更新失败，使用缓存：$_url"
            cat "$_cache" >>"$_all"
        else
            warn "URL 更新失败且没有缓存：$_url"
        fi
    done

    for _domain in $SOURCES_DOMAINS; do
        _cache=$(source_cache_path "domain" "$_domain")
        if resolve_domain "$_domain" "$_raw"; then
            cat "$_raw" | sort -u >"$_cache"
            cat "$_cache" >>"$_all"
            log "域名已解析：$_domain"
        elif [ -s "$_cache" ]; then
            warn "域名解析失败，使用缓存：$_domain"
            cat "$_cache" >>"$_all"
        else
            warn "域名解析失败且没有缓存：$_domain"
        fi
    done

    sort -u "$_all" >"$_tmpdir/all.sorted"
    split_ip_versions "$_tmpdir/all.sorted" "$_tmpdir/v4.txt" "$_tmpdir/v6.txt"

    cp "$_tmpdir/v4.txt" "$(state_path "$PROTO" "$PORT" "allow4")"
    cp "$_tmpdir/v6.txt" "$(state_path "$PROTO" "$PORT" "allow6")"
    date +%s >"$(state_path "$PROTO" "$PORT" "last")"

    _v4_count=$(wc -l <"$_tmpdir/v4.txt" | awk '{print $1}')
    _v6_count=$(wc -l <"$_tmpdir/v6.txt" | awk '{print $1}')
    rm -rf "$_tmpdir"

    if [ "$_v4_count" -eq 0 ] && [ "$_v6_count" -eq 0 ]; then
        warn "$PROTO/$PORT 当前白名单为空，应用后该端口将拒绝所有来源"
    fi
    log "$PROTO/$PORT 白名单已刷新：IPv4=$_v4_count IPv6=$_v6_count"
}

ipset_load_file() {
    _family="$1"
    _set="$2"
    _file="$3"
    _optional="${4:-0}"

    if ! command -v ipset >/dev/null 2>&1; then
        [ "$_optional" -eq 1 ] && { warn "缺少 ipset，跳过可选集合：$_set"; return 1; }
        die "缺少 ipset，请先运行：port-guard install"
    fi
    [ -f "$_file" ] || : >"$_file"

    if ! ipset create "$_set" hash:net family "$_family" hashsize 1024 maxelem "$MAXELEM" -exist >/dev/null 2>&1; then
        [ "$_optional" -eq 1 ] && { warn "无法创建可选 ipset：$_set"; return 1; }
        die "无法创建 ipset：$_set"
    fi

    _new="${_set}_new"
    ipset destroy "$_new" >/dev/null 2>&1 || true
    if ! ipset create "$_new" hash:net family "$_family" hashsize 1024 maxelem "$MAXELEM" >/dev/null 2>&1; then
        [ "$_optional" -eq 1 ] && { warn "无法创建可选临时 ipset：$_new"; return 1; }
        die "无法创建临时 ipset：$_new"
    fi

    _ok=0
    _bad=0
    while IFS= read -r _entry; do
        [ -n "$_entry" ] || continue
        if ipset add "$_new" "$_entry" -exist >/dev/null 2>&1; then
            _ok=$((_ok + 1))
        else
            _bad=$((_bad + 1))
        fi
    done <"$_file"

    if ! ipset swap "$_new" "$_set" >/dev/null 2>&1; then
        ipset destroy "$_new" >/dev/null 2>&1 || true
        [ "$_optional" -eq 1 ] && { warn "无法切换可选 ipset：$_set"; return 1; }
        die "无法切换 ipset：$_set"
    fi
    ipset destroy "$_new" >/dev/null 2>&1 || true
    [ "$_bad" -eq 0 ] || warn "$_set 忽略了 $_bad 条无效 IP/CIDR"
    log "$_set 已载入 $_ok 条"
}

ensure_family_rules() {
    _family="$1"
    _cmd="$2"
    _proto="$3"
    _port="$4"
    _chain="$5"
    _set="$6"
    _action="$7"

    if ! command -v "$_cmd" >/dev/null 2>&1; then
        warn "缺少 $_cmd，无法保护 IPv$_family 流量：$_proto/$_port"
        return 0
    fi

    "$_cmd" -N "$_chain" >/dev/null 2>&1 || true
    "$_cmd" -F "$_chain" >/dev/null || die "无法清空 chain：$_chain"

    "$_cmd" -A "$_chain" -m set --match-set "$_set" src -j ACCEPT >/dev/null || die "$_cmd 不支持 ipset 匹配，无法应用 $_proto/$_port"
    if [ "$_action" = "REJECT" ]; then
        "$_cmd" -A "$_chain" -j REJECT >/dev/null || die "无法添加 REJECT 规则"
    else
        "$_cmd" -A "$_chain" -j DROP >/dev/null || die "无法添加 DROP 规则"
    fi

    while "$_cmd" -D INPUT -p "$_proto" --dport "$_port" -j "$_chain" >/dev/null 2>&1; do
        :
    done
    "$_cmd" -I INPUT 1 -p "$_proto" --dport "$_port" -j "$_chain" >/dev/null || die "无法挂载 INPUT 规则：$_proto/$_port"
}

apply_one() {
    _proto="$1"
    _port="$2"
    load_config "$_proto" "$_port"
    mkdirs

    _allow4=$(state_path "$PROTO" "$PORT" "allow4")
    _allow6=$(state_path "$PROTO" "$PORT" "allow6")
    if [ ! -f "$_allow4" ] && [ ! -f "$_allow6" ]; then
        refresh_one "$PROTO" "$PORT"
    fi

    _chain=$(chain_name "$PROTO" "$PORT")
    _set4=$(set4_name "$PROTO" "$PORT")
    _set6=$(set6_name "$PROTO" "$PORT")

    ipset_load_file inet "$_set4" "$_allow4"

    ensure_family_rules 4 iptables "$PROTO" "$PORT" "$_chain" "$_set4" "$ACTION"
    if command -v ip6tables >/dev/null 2>&1; then
        if ipset_load_file inet6 "$_set6" "$_allow6" 1; then
            ensure_family_rules 6 ip6tables "$PROTO" "$PORT" "$_chain" "$_set6" "$ACTION"
        else
            warn "IPv6 ipset 不可用，已跳过 IPv6 保护：$PROTO/$PORT"
        fi
    else
        warn "缺少 ip6tables，无法保护 IPv6 流量：$PROTO/$PORT"
    fi
    log "$PROTO/$PORT 规则已应用，只影响该协议端口"
}

due_one() {
    _proto="$1"
    _port="$2"
    load_config "$_proto" "$_port"
    _last_file=$(state_path "$PROTO" "$PORT" "last")
    _now=$(date +%s)
    _last=0
    [ -f "$_last_file" ] && _last=$(cat "$_last_file" 2>/dev/null || printf '0')
    case "$_last" in ''|*[!0-9]*) _last=0 ;; esac
    _elapsed=$((_now - _last))
    _interval=$((INTERVAL_MINUTES * 60))
    [ "$_elapsed" -ge "$_interval" ]
}

delete_family_rules() {
    _cmd="$1"
    _proto="$2"
    _port="$3"
    _chain="$4"
    if command -v "$_cmd" >/dev/null 2>&1; then
        while "$_cmd" -D INPUT -p "$_proto" --dport "$_port" -j "$_chain" >/dev/null 2>&1; do
            :
        done
        "$_cmd" -F "$_chain" >/dev/null 2>&1 || true
        "$_cmd" -X "$_chain" >/dev/null 2>&1 || true
    fi
}

delete_one() {
    _proto="$1"
    _port="$2"
    validate_port "$_port"
    validate_proto "$_proto"

    _chain=$(chain_name "$_proto" "$_port")
    _set4=$(set4_name "$_proto" "$_port")
    _set6=$(set6_name "$_proto" "$_port")

    delete_family_rules iptables "$_proto" "$_port" "$_chain"
    delete_family_rules ip6tables "$_proto" "$_port" "$_chain"

    if command -v ipset >/dev/null 2>&1; then
        ipset destroy "$_set4" >/dev/null 2>&1 || true
        ipset destroy "${_set4}_new" >/dev/null 2>&1 || true
        ipset destroy "$_set6" >/dev/null 2>&1 || true
        ipset destroy "${_set6}_new" >/dev/null 2>&1 || true
    fi

    rm -f "$(conf_path "$_proto" "$_port")"
    rm -f "$(state_path "$_proto" "$_port" "allow4")" \
          "$(state_path "$_proto" "$_port" "allow6")" \
          "$(state_path "$_proto" "$_port" "last")"
    log "已删除 $_proto/$_port 的全部 port-guard 规则"
}

for_each_config() {
    _cmd="$1"
    _found=0
    for _conf in "$CONFIG_DIR"/*.conf; do
        [ -f "$_conf" ] || continue
        _found=1
        PORT=''
        PROTO=''
        # shellcheck disable=SC1090
        . "$_conf"
        [ -n "$PORT" ] && [ -n "$PROTO" ] || continue
        "$_cmd" "$PROTO" "$PORT"
    done
    [ "$_found" -eq 1 ]
}

install_packages() {
    _need_iptables=0
    _need_ipset=0
    _need_fetcher=0

    command -v iptables >/dev/null 2>&1 || _need_iptables=1
    command -v ipset >/dev/null 2>&1 || _need_ipset=1
    if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1 && ! command -v fetch >/dev/null 2>&1; then
        _need_fetcher=1
    fi

    [ "$_need_iptables" -eq 0 ] && [ "$_need_ipset" -eq 0 ] && [ "$_need_fetcher" -eq 0 ] && return 0

    if command -v apk >/dev/null 2>&1; then
        log "正在用 apk 安装依赖：iptables ipset curl"
        apk add --no-cache iptables ipset curl || warn "apk 安装依赖失败，请手动安装 iptables/ipset/curl"
        return 0
    fi

    if command -v apt-get >/dev/null 2>&1; then
        log "正在用 apt-get 安装依赖：iptables ipset curl"
        apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y iptables ipset curl || warn "apt-get 安装依赖失败，请手动安装 iptables/ipset/curl"
        return 0
    fi

    warn "未识别包管理器，请手动安装 iptables、ipset，以及 curl/wget/fetch 之一"
}

start_cron_best_effort() {
    if command -v systemctl >/dev/null 2>&1; then
        systemctl enable --now cron >/dev/null 2>&1 || systemctl enable --now crond >/dev/null 2>&1 || true
    fi
    if command -v rc-update >/dev/null 2>&1; then
        rc-update add crond default >/dev/null 2>&1 || true
    fi
    if command -v rc-service >/dev/null 2>&1; then
        rc-service crond start >/dev/null 2>&1 || true
    fi
    if command -v service >/dev/null 2>&1; then
        service cron start >/dev/null 2>&1 || service crond start >/dev/null 2>&1 || true
    fi
}

install_update_scheduler() {
    _line="$BIN_PATH update due --quiet"
    if command -v systemctl >/dev/null 2>&1 && [ -d /etc/systemd/system ]; then
        {
            printf '[Unit]\n'
            printf 'Description=Port Guard due update\n\n'
            printf '[Service]\n'
            printf 'Type=oneshot\n'
            printf 'ExecStart=%s\n' "$_line"
        } >/etc/systemd/system/port-guard-update.service
        {
            printf '[Unit]\n'
            printf 'Description=Run Port Guard due update every minute\n\n'
            printf '[Timer]\n'
            printf 'OnBootSec=1min\n'
            printf 'OnUnitActiveSec=1min\n'
            printf 'AccuracySec=30s\n'
            printf 'Unit=port-guard-update.service\n\n'
            printf '[Install]\n'
            printf 'WantedBy=timers.target\n'
        } >/etc/systemd/system/port-guard-update.timer
        systemctl daemon-reload >/dev/null 2>&1 || true
        if systemctl enable --now port-guard-update.timer >/dev/null 2>&1; then
            log "已安装定时更新：systemd port-guard-update.timer"
            return 0
        fi
        warn "systemd timer 写入成功但启用失败，继续尝试 cron"
    fi

    if [ -d /etc/cron.d ]; then
        {
            printf 'SHELL=/bin/sh\n'
            printf 'PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n'
            printf '# port-guard managed update\n'
            printf '* * * * * root %s\n' "$_line"
        } >/etc/cron.d/port-guard
        chmod 644 /etc/cron.d/port-guard 2>/dev/null || true
        log "已安装定时更新：/etc/cron.d/port-guard"
        start_cron_best_effort
        return 0
    fi

    if command -v crontab >/dev/null 2>&1; then
        _tmp=$(mktemp "${TMPDIR:-/tmp}/port-guard-cron.XXXXXX") || return 1
        crontab -l 2>/dev/null | awk '!/port-guard update due/' >"$_tmp"
        {
            printf '# port-guard managed update\n'
            printf '* * * * * %s\n' "$_line"
        } >>"$_tmp"
        crontab "$_tmp" && rm -f "$_tmp"
        log "已安装 root crontab 定时更新"
        start_cron_best_effort
        return 0
    fi

    if [ -d /etc/crontabs ]; then
        _file=/etc/crontabs/root
        touch "$_file"
        _tmp=$(mktemp "${TMPDIR:-/tmp}/port-guard-cron.XXXXXX") || return 1
        awk '!/port-guard update due/' "$_file" >"$_tmp"
        {
            printf '# port-guard managed update\n'
            printf '* * * * * %s\n' "$_line"
        } >>"$_tmp"
        cat "$_tmp" >"$_file"
        rm -f "$_tmp"
        log "已安装 /etc/crontabs/root 定时更新"
        start_cron_best_effort
        return 0
    fi

    warn "没有找到 cron，无法自动定时更新；可手动周期执行：$BIN_PATH update due"
}

install_boot_service() {
    if command -v systemctl >/dev/null 2>&1 && [ -d /etc/systemd/system ]; then
        {
            printf '[Unit]\n'
            printf 'Description=Port Guard firewall restore\n'
            printf 'After=network-online.target\n'
            printf 'Wants=network-online.target\n\n'
            printf '[Service]\n'
            printf 'Type=oneshot\n'
            printf 'ExecStart=%s apply all --quiet\n' "$BIN_PATH"
            printf 'RemainAfterExit=yes\n\n'
            printf '[Install]\n'
            printf 'WantedBy=multi-user.target\n'
        } >/etc/systemd/system/port-guard.service
        systemctl daemon-reload >/dev/null 2>&1 || true
        if systemctl enable port-guard.service >/dev/null 2>&1; then
            log "已安装开机恢复服务：systemd port-guard.service"
            return 0
        fi
        warn "systemd 服务写入成功但启用失败，继续尝试其它开机恢复方式"
    fi

    if command -v rc-update >/dev/null 2>&1 && [ -d /etc/local.d ]; then
        {
            printf '#!/bin/sh\n'
            printf '%s apply all --quiet\n' "$BIN_PATH"
        } >/etc/local.d/port-guard.start
        chmod +x /etc/local.d/port-guard.start
        rc-update add local default >/dev/null 2>&1 || true
        log "已安装开机恢复脚本：/etc/local.d/port-guard.start"
        return 0
    fi

    if command -v crontab >/dev/null 2>&1; then
        _tmp=$(mktemp "${TMPDIR:-/tmp}/port-guard-reboot.XXXXXX") || return 1
        crontab -l 2>/dev/null | awk '!/port-guard apply all/' >"$_tmp"
        printf '@reboot %s apply all --quiet\n' "$BIN_PATH" >>"$_tmp"
        crontab "$_tmp" && rm -f "$_tmp"
        log "已安装 @reboot 开机恢复"
        return 0
    fi

    warn "未能安装开机恢复；重启后请手动运行：$BIN_PATH apply all"
}

remove_schedulers() {
    if command -v systemctl >/dev/null 2>&1; then
        systemctl disable --now port-guard.service >/dev/null 2>&1 || true
        systemctl disable --now port-guard-update.timer >/dev/null 2>&1 || true
        systemctl daemon-reload >/dev/null 2>&1 || true
    fi
    rm -f /etc/cron.d/port-guard \
          /etc/systemd/system/port-guard.service \
          /etc/systemd/system/port-guard-update.service \
          /etc/systemd/system/port-guard-update.timer \
          /etc/local.d/port-guard.start 2>/dev/null || true
    if command -v crontab >/dev/null 2>&1; then
        _tmp=$(mktemp "${TMPDIR:-/tmp}/port-guard-cron.XXXXXX") || return 0
        crontab -l 2>/dev/null | awk '!/port-guard update due/ && !/port-guard apply all/ && !/port-guard managed update/' >"$_tmp"
        crontab "$_tmp" >/dev/null 2>&1 || true
        rm -f "$_tmp"
    fi
    if command -v systemctl >/dev/null 2>&1; then
        systemctl daemon-reload >/dev/null 2>&1 || true
    fi
}

install_command() {
    need_root "$@"
    _install_deps=1
    _install_scheduler=1
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --no-deps) _install_deps=0 ;;
            --no-scheduler) _install_scheduler=0 ;;
            --quiet|-q) ;;
            *) die "未知 install 参数：$1" ;;
        esac
        shift
    done

    mkdirs
    _self=$(self_path)
    [ -r "$_self" ] || die "无法读取当前脚本路径：$_self"
    mkdir -p "$(dirname "$BIN_PATH")"
    if [ "$_self" != "$BIN_PATH" ]; then
        cp "$_self" "$BIN_PATH" || die "无法安装到 $BIN_PATH"
    fi
    chmod +x "$BIN_PATH"
    log "已安装命令：$BIN_PATH"

    [ "$_install_deps" -eq 1 ] && install_packages
    if [ "$_install_scheduler" -eq 1 ]; then
        install_boot_service
        install_update_scheduler
    fi
}

add_command() {
    need_root "$@"
    _port=''
    _proto='tcp'
    _action='DROP'
    _interval='30'
    _ips=''
    _files=''
    _urls=''
    _domains=''
    _apply=1

    while [ "$#" -gt 0 ]; do
        case "$1" in
            --port|-p) shift; _port="$1" ;;
            --proto) shift; _proto="$(lower "$1")" ;;
            --action) shift; _action="$(upper "$1")" ;;
            --interval) shift; _interval="$1" ;;
            --ip) shift; _ips="$_ips $1" ;;
            --ips) shift; _ips="$_ips $(trim_list "$1")" ;;
            --ip-file|--file) shift; _files="$_files $1" ;;
            --url) shift; _urls="$_urls $1" ;;
            --domain) shift; _domains="$_domains $1" ;;
            --no-apply) _apply=0 ;;
            --quiet|-q) ;;
            *) die "未知 add 参数：$1" ;;
        esac
        shift
    done

    [ -n "$_port" ] || die "缺少 --port"
    validate_port "$_port"
    validate_proto "$_proto"

    if [ "$_proto" = "both" ]; then
        write_config_one tcp "$_port" "$_action" "$_interval" "$_ips" "$_files" "$_urls" "$_domains"
        write_config_one udp "$_port" "$_action" "$_interval" "$_ips" "$_files" "$_urls" "$_domains"
        if [ "$_apply" -eq 1 ]; then
            refresh_one tcp "$_port"
            apply_one tcp "$_port"
            refresh_one udp "$_port"
            apply_one udp "$_port"
        fi
    else
        write_config_one "$_proto" "$_port" "$_action" "$_interval" "$_ips" "$_files" "$_urls" "$_domains"
        if [ "$_apply" -eq 1 ]; then
            refresh_one "$_proto" "$_port"
            apply_one "$_proto" "$_port"
        fi
    fi
    install_update_scheduler >/dev/null 2>&1 || true
}

apply_command() {
    need_root "$@"
    _target="${1:-all}"
    case "$_target" in
        all|'')
            for_each_config apply_one || log "暂无规则"
            ;;
        *)
            _proto="${1:-}"
            _port="${2:-}"
            [ -n "$_proto" ] && [ -n "$_port" ] || die "用法：port-guard apply <tcp|udp> <port>"
            apply_one "$_proto" "$_port"
            ;;
    esac
}

update_command() {
    need_root "$@"
    acquire_update_lock
    _mode="${1:-all}"
    case "$_mode" in
        all|'')
            _found=0
            for _conf in "$CONFIG_DIR"/*.conf; do
                [ -f "$_conf" ] || continue
                _found=1
                PORT=''
                PROTO=''
                # shellcheck disable=SC1090
                . "$_conf"
                [ -n "$PORT" ] && [ -n "$PROTO" ] || continue
                refresh_one "$PROTO" "$PORT"
                apply_one "$PROTO" "$PORT"
            done
            [ "$_found" -eq 1 ] || log "暂无规则"
            ;;
        due)
            _found=0
            for _conf in "$CONFIG_DIR"/*.conf; do
                [ -f "$_conf" ] || continue
                _found=1
                PORT=''
                PROTO=''
                # shellcheck disable=SC1090
                . "$_conf"
                [ -n "$PORT" ] && [ -n "$PROTO" ] || continue
                if due_one "$PROTO" "$PORT"; then
                    refresh_one "$PROTO" "$PORT"
                    apply_one "$PROTO" "$PORT"
                fi
            done
            [ "$_found" -eq 1 ] || log "暂无规则"
            ;;
        *)
            _proto="${1:-}"
            _port="${2:-}"
            [ -n "$_proto" ] && [ -n "$_port" ] || die "用法：port-guard update [all|due|<tcp|udp> <port>]"
            refresh_one "$_proto" "$_port"
            apply_one "$_proto" "$_port"
            ;;
    esac
    release_update_lock
}

delete_command() {
    need_root "$@"
    _proto=''
    _port=''
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --port|-p) shift; _port="$1" ;;
            --proto) shift; _proto="$(lower "$1")" ;;
            --quiet|-q) ;;
            *)
                if [ -z "$_proto" ]; then _proto="$(lower "$1")"
                elif [ -z "$_port" ]; then _port="$1"
                else die "未知 delete 参数：$1"
                fi
                ;;
        esac
        shift
    done
    [ -n "$_proto" ] && [ -n "$_port" ] || die "用法：port-guard delete --proto <tcp|udp|both> --port <port>"
    validate_proto "$_proto"
    validate_port "$_port"
    if [ "$_proto" = "both" ]; then
        delete_one tcp "$_port"
        delete_one udp "$_port"
    else
        delete_one "$_proto" "$_port"
    fi
}

reset_command() {
    need_root "$@"
    _confirm="${1:-}"
    if [ "$_confirm" != "--yes" ] && [ "$QUIET" -ne 1 ]; then
        printf '确认删除所有 port-guard 管理的端口规则和配置？输入 YES 继续：'
        IFS= read -r _ans
        [ "$_ans" = "YES" ] || die "已取消"
    fi
    for_each_config delete_one || true
    rm -f "$STATE_DIR"/cache_*.txt 2>/dev/null || true
    log "已重置所有 port-guard 规则"
}

uninstall_command() {
    need_root "$@"
    reset_command --yes
    remove_schedulers
    rm -f "$BIN_PATH"
    rmdir "$CONFIG_DIR" "$BASE_DIR" "$STATE_DIR" "$RUN_DIR" 2>/dev/null || true
    log "已卸载 port-guard"
}

status_one() {
    _proto="$1"
    _port="$2"
    load_config "$_proto" "$_port"
    _allow4=$(state_path "$PROTO" "$PORT" "allow4")
    _allow6=$(state_path "$PROTO" "$PORT" "allow6")
    _v4=0
    _v6=0
    [ -f "$_allow4" ] && _v4=$(wc -l <"$_allow4" | awk '{print $1}')
    [ -f "$_allow6" ] && _v6=$(wc -l <"$_allow6" | awk '{print $1}')
    printf '%s/%s action=%s interval=%sm IPv4=%s IPv6=%s\n' "$PROTO" "$PORT" "$ACTION" "$INTERVAL_MINUTES" "$_v4" "$_v6"
}

status_command() {
    need_root "$@"
    _found=0
    for _conf in "$CONFIG_DIR"/*.conf; do
        [ -f "$_conf" ] || continue
        _found=1
        PORT=''
        PROTO=''
        # shellcheck disable=SC1090
        . "$_conf"
        [ -n "$PORT" ] && [ -n "$PROTO" ] || continue
        status_one "$PROTO" "$PORT"
    done
    [ "$_found" -eq 1 ] || log "暂无规则"
}

ask_default() {
    _prompt="$1"
    _default="$2"
    if [ -n "$_default" ]; then
        printf '%s [%s]: ' "$_prompt" "$_default" >&2
    else
        printf '%s: ' "$_prompt" >&2
    fi
    IFS= read -r _ans
    [ -n "$_ans" ] || _ans="$_default"
    printf '%s' "$_ans"
}

interactive_add() {
    _port=$(ask_default "端口" "443")
    _proto=$(ask_default "协议 tcp/udp/both" "tcp")
    _ips=$(ask_default "固定 IP/CIDR，多个用空格或逗号分隔，可留空" "")
    _files=$(ask_default "本地 IP 列表文件路径，多个用空格分隔，可留空" "")
    _urls=$(ask_default "远程 IP 列表 URL，多个用空格分隔，可留空" "")
    _domains=$(ask_default "允许访问的域名，多个用空格分隔，可留空" "")
    _interval=$(ask_default "URL/域名更新间隔，单位分钟" "30")
    _action=$(ask_default "非白名单来源动作 DROP/REJECT" "DROP")

    add_command --port "$_port" --proto "$_proto" --ips "$_ips" --action "$_action" --interval "$_interval" \
        --file "$_files" --url "$_urls" --domain "$_domains"
}

interactive_delete() {
    _port=$(ask_default "要删除的端口" "443")
    _proto=$(ask_default "协议 tcp/udp/both" "tcp")
    delete_command --port "$_port" --proto "$_proto"
}

interactive_menu() {
    need_root "$@"
    while :; do
        printf '\n'
        printf 'Port Guard %s\n' "$VERSION"
        printf '1) 安装/修复依赖、开机恢复和定时更新\n'
        printf '2) 新增或覆盖端口白名单规则\n'
        printf '3) 查看规则状态\n'
        printf '4) 立即更新并应用全部规则\n'
        printf '5) 删除某个端口的所有规则\n'
        printf '6) 重置所有 port-guard 规则\n'
        printf '7) 卸载 port-guard\n'
        printf '0) 退出\n'
        printf '请选择: '
        IFS= read -r _choice
        case "$_choice" in
            1) install_command ;;
            2) interactive_add ;;
            3) status_command ;;
            4) update_command all ;;
            5) interactive_delete ;;
            6) reset_command ;;
            7) uninstall_command ;;
            0) exit 0 ;;
            *) printf '无效选择\n' ;;
        esac
    done
}

usage() {
    cat <<'EOF'
Port Guard - 单端口来源白名单防火墙

交互模式：
  sudo ./port-guard.sh

安装到系统：
  sudo ./port-guard.sh install

新增/覆盖规则：
  sudo port-guard add --port 443 --proto tcp \
    --ip 1.2.3.4 --ips "5.6.7.0/24,8.8.8.8" \
    --file /root/allow.txt \
    --url https://example.com/allow.txt \
    --domain example.com \
    --interval 30

常用命令：
  sudo port-guard update all
  sudo port-guard update due
  sudo port-guard apply all
  sudo port-guard delete --proto tcp --port 443
  sudo port-guard delete --proto both --port 443
  sudo port-guard reset
  sudo port-guard status

说明：
  - 仅在 INPUT 链挂载指定协议/端口的专用 chain，不改其它端口规则。
  - 白名单用 ipset 存储，URL/域名失败时会回退到上次成功缓存。
  - 定时任务每分钟检查一次，但每条规则按自己的 interval 决定是否更新。
EOF
}

main() {
    _cmd="${1:-}"
    case "$_cmd" in
        '') interactive_menu ;;
        install) shift; install_command "$@" ;;
        add|create) shift; add_command "$@" ;;
        apply) shift; apply_command "$@" ;;
        update|refresh) shift; update_command "$@" ;;
        delete|remove|del) shift; delete_command "$@" ;;
        reset) shift; reset_command "$@" ;;
        uninstall) shift; uninstall_command "$@" ;;
        status|list) shift; status_command "$@" ;;
        help|-h|--help) usage ;;
        version|--version) printf '%s\n' "$VERSION" ;;
        --quiet|-q) shift; main "$@" ;;
        *) usage; exit 1 ;;
    esac
}

main "$@"
