#!/bin/bash
Z="{{DOMAIN_ZONE}}"
K=({{KEY_SPACE}})
enc(){
  local s="$1" h="" i=0
  while [ $i -lt ${#s} ];do
    local c=$(printf '%d' "'${s:$i:1}")
    local x=$(( c ^ K[i%4] ))
    h+=$(printf '%02x' $x)
    ((i++))
  done
  echo "$h"
}
dec(){
  local h="$1" s="" i=0
  while [ $i -lt ${#h} ];do
    local v=$((16#${h:$i:2}))
    local x=$(( v ^ K[i/2%4] ))
    s+=$(printf "\\x$(printf '%02x' $x)")
    ((i+=2))
  done
  echo "$s"
}
echo "=== Tracer Terminal Chat (Bash) ==="
echo "Type message, Enter to send. /quit to exit."
while true;do
  read -p "you: " M
  [ "$M" = "/quit" ] && { traceroute -m 1 -w 1 "end.$Z" >/dev/null 2>&1;echo "Disconnected.";break; }
  H=$(enc "$M")
  traceroute -m 1 -w 1 "$H.tx.$Z" >/dev/null 2>&1
  R=""
  while IFS= read -r line;do
    if echo "$line"|grep -qi "$Z";then
      if ! echo "$line"|grep -qiE "(end|empty|rx)\.$Z";then
        w=$(echo "$line"|grep -oP '\S+(?=\.'"$Z"')')
        [ -n "$w" ] && R+=$(echo "$w"|tr '.' '\n'|grep -E '^[0-9a-fA-F]+$'|while read -r lbl; do [ $((${#lbl}%2)) -eq 0 ] && printf "%s" "$lbl"; done)
      fi
    fi
  done < <(traceroute -w 2 "rx.$Z" 2>&1)
  if [ -n "$R" ];then
    echo "server: $(dec "$R")"
  fi
  sleep {{POLL_RATE}}
done
