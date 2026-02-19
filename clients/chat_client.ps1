$Z="lab.mydomain.net"
$K=[byte[]]@(96,38,118,3)
function X($b){$o=New-Object byte[] $b.Length;for($i=0;$i-lt$b.Length;$i++){$o[$i]=$b[$i]-bxor$K[$i%4]};$o}
function Enc($s){$b=X([text.encoding]::UTF8.GetBytes($s));-join($b|%{$_.ToString('x2')})}
function Dec($h){if(!$h){return ""};$b=New-Object byte[]($h.Length/2);for($i=0;$i-lt$b.Length;$i++){$b[$i]=[convert]::ToByte($h.Substring($i*2,2),16)};[text.encoding]::UTF8.GetString((X $b))}
Write-Host "=== Tracer Terminal Chat (PS) ==="
Write-Host "Type message, Enter to send. /quit to exit."
while($true){
$M=Read-Host "you"
if($M-eq"/quit"){tracert -h 1 -w 1000 "end.$Z"|Out-Null;Write-Host "Disconnected.";break}
$H=Enc $M
tracert -h 1 -w 1000 "$H.tx.$Z" 2>&1|Out-Null
$t=tracert -w 2000 "rx.$Z" 2>&1
$R=""
$t|?{$_-match"\.${Z}"}|?{$_-notmatch"(end|empty|rx)\.$Z"}|?{$_-notmatch"Tracing"}|%{
if($_-match"(\S+)\.$Z"){$d=$Matches[1]-replace"\.$Z","";$R+=$d-replace"\.",""}}
if($R){Write-Host "server: $(Dec $R)";tracert -h 1 -w 1000 "ack.$Z" 2>&1|Out-Null}
}
