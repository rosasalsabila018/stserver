#!/bin/bash
# slowdns-hook: NOTRACK per-IP untuk UDP 53 (dipasang saat start, dilepas saat stop).
# Gagal memasang NOTRACK TIDAK menggagalkan SlowDNS (hanya optimasi conntrack).
set -u
MARKER=slowdns-direct
warn() { printf 'slowdns-hook: %s\n' "$*" >&2; }
[ "$#" -ge 4 ] && [ "$1" = __network ] && [ "$3" = bindings ] || { warn "argumen tidak valid"; exit 0; }
action="$2"; listener="$4"; shift 4
case "$action" in start|stop) ;; *) warn "aksi tidak valid"; exit 0 ;; esac
[ "$#" -ge 1 ] || exit 0
[ "${listener##*:}" = 53 ] || exit 0
valid_binding() {
  [[ "$1" =~ ^[A-Fa-f0-9:.]+,[A-Za-z0-9_][A-Za-z0-9_.:-]*$ ]] || return 1
  case "${1%%,*}" in 0.*|127.*|::|::1) return 1 ;; esac
  return 0
}
assigned() {
  local host rows4="" rows6=""
  host="${1%:*}"; host="${host#\[}"; host="${host%\]}"
  case "$host" in ''|0.0.0.0|::) host="" ;; esac
  if [ -n "$host" ]; then
    case "$host" in
      *:*) rows6="$(ip -o -6 address show scope global to "$host/128" 2>/dev/null || true)" ;;
      *)   rows4="$(ip -o -4 address show scope global to "$host/32"  2>/dev/null || true)" ;;
    esac
  else
    rows4="$(ip -o -4 address show scope global 2>/dev/null || true)"
    rows6="$(ip -o -6 address show scope global 2>/dev/null || true)"
  fi
  printf '%s\n%s\n' "$rows4" "$rows6" \
    | awk '($3=="inet"||$3=="inet6") && $0 !~ / (tentative|dadfailed) / { sub(/@.*/, "", $2); split($4, a, "/"); print a[1] "," $2 }'
}
raw_rule() {
  local tool="$1" act="$2" chain="$3" st; shift 3
  if "$tool" -w 5 -t raw -C "$chain" "$@" 2>/dev/null; then
    [ "$act" = start ] || "$tool" -w 5 -t raw -D "$chain" "$@"
  else
    st=$?
    [ "$st" -eq 1 ] || return "$st"
    [ "$act" = stop ] || "$tool" -w 5 -t raw -I "$chain" 1 "$@"
  fi
}
network_rules() {   # $1=aksi $2=ip $3=interface
  local tool=iptables
  case "$2" in *:*) tool=ip6tables ;; esac
  command -v "$tool" >/dev/null 2>&1 || return 127
  raw_rule "$tool" "$1" PREROUTING -i "$3" -d "$2" -p udp --dport 53 -m comment --comment "$MARKER" -j CT --notrack || return $?
  raw_rule "$tool" "$1" OUTPUT -s "$2" -p udp --sport 53 -m comment --comment "$MARKER" -j CT --notrack
}
allowed=""
if [ "$action" = start ]; then
  allowed="$(assigned "$listener")" || allowed=""
  allowed=" ${allowed//$'\n'/ } "
fi
todo=(); status=0
for b in "$@"; do
  valid_binding "$b" || { warn "binding tidak valid: $b"; continue; }
  if [ "$action" = start ]; then
    case "$allowed" in *" $b "*) ;; *) warn "IP tidak terpasang, dilewati: $b"; continue ;; esac
  fi
  todo+=("$b")
done
if [ "${#todo[@]}" -gt 0 ]; then
  for b in "${todo[@]}"; do
    if network_rules "$action" "${b%%,*}" "${b#*,}"; then continue; else status=$?; fi
    if [ "$action" = start ]; then      # gagal: batalkan semua yang sempat terpasang
      for bb in "${todo[@]}"; do network_rules stop "${bb%%,*}" "${bb#*,}" >/dev/null 2>&1 || true; done
      warn "NOTRACK tidak terpasang (status $status); SlowDNS tetap berjalan"
      break
    fi
  done
fi
[ "$action" = start ] && exit 0
exit "$status"
