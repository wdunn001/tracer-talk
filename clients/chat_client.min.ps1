$Z="{{DOMAIN_ZONE}}";$K=[byte[]]@({{KEY_CSV}})
function X($b){$o=New-Object byte[] $b.Length;for($i=0;$i-lt$b.Length;$i++){$o[$i]=$b[$i]-bxor$K[$i%4]};$o}
function E($s){-join(X([text.encoding]::UTF8.GetBytes($s))|%{$_.ToString('x2')})}
function D($h){if(!$h){return ""};$b=New-Object byte[]($h.Length/2);for($i=0;$i-lt$b.Length;$i++){$b[$i]=[convert]::ToByte($h.Substring($i*2,2),16)};[text.encoding]::UTF8.GetString(X $b)}
for(){$M=Read-Host "you";if($M-eq"/quit"){tracert -h 1 -w 1000 "end.$Z"|Out-Null;break}
tracert -h 1 -w 1000 "$(E $M).tx.$Z" 2>&1|Out-Null;$R="";tracert -w 2000 "rx.$Z" 2>&1|?{$_-match"\.${Z}"-and$_-notmatch"(end|empty|rx|Tracing)"}|%{if($_-match"(\S+)\.$Z"){$R+=($Matches[1]-replace"\.","")}};if($R){Write-Host "< $(D $R)";tracert -h 1 -w 1000 "ack.$Z" 2>&1|Out-Null}}
