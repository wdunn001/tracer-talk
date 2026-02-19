#!/bin/bash
Z="{{DOMAIN_ZONE}}";K=({{KEY_SPACE}})
e(){ local s="$1" h="" i=0;while [ $i -lt ${#s} ];do h+=$(printf '%02x' $(( $(printf '%d' "'${s:$i:1}") ^ K[i%4] )));((i++));done;echo "$h";}
d(){ local h="$1" s="" i=0;while [ $i -lt ${#h} ];do s+=$(printf "\\x$(printf '%02x' $(( 16#${h:$i:2} ^ K[i/2%4] )))");((i+=2));done;echo "$s";}
while read -p "you: " M;do
[ "$M" = "/quit" ]&&{ traceroute -m1 -w1 "end.$Z">/dev/null 2>&1;break;}
traceroute -m1 -w1 "$(e "$M").tx.$Z">/dev/null 2>&1;R=""
while IFS= read -r l;do echo "$l"|grep -qi "$Z"&&! echo "$l"|grep -qiE "(end|empty|rx)\.$Z"&&{ w=$(echo "$l"|grep -oP '\S+(?=\.'"$Z"')');[ -n "$w" ]&&R+="${w//./}";}
done< <(traceroute -w2 "rx.$Z" 2>&1)
[ -n "$R" ]&&{ echo "< $(d "$R")";traceroute -m1 -w1 "ack.$Z">/dev/null 2>&1;}
done
