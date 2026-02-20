@echo off
setlocal enabledelayedexpansion
set S={{SERVER_IP}}
set Z={{DOMAIN_ZONE}}
echo === Tracer Terminal Chat ===
echo Type message, Enter to send. /quit to exit.
:L
set /p "M=you: "
if /i "!M!"=="/quit" goto Q
for /f %%h in ('powershell -nop -c "$k=@({{KEY_CSV}});$m=[text.encoding]::UTF8.GetBytes('%M%');-join($m|%%{(($_-bxor$k[$i++%%4]).ToString('x2'))})"') do set H=%%h
tracert -h 1 -w 1000 !H!.tx.!Z! >nul 2>&1
tracert -w 2000 rx.!Z! >%tmp%\rx.txt 2>&1
for /f "delims=" %%d in ('powershell -nop -c "$t=gc $env:tmp\rx.txt;$tok=@($t|%%{($_ -split '\s+')|?{$_ -match '\.' -and $_ -match '\.[^.]+\.[^.]+\.'}});$h=($tok|%%{if($_.StartsWith('end.')){break};($_ -split '\.'|?{$_.Length%%2 -eq 0 -and $_ -match '^[0-9a-f]+$'})-join''})-join'';if($h){$k=@({{KEY_CSV}});$b=for($i=0;$i-lt$h.Length;$i+=2){[byte]([convert]::ToByte($h.Substring($i,2),16)-bxor$k[($i/2)%%4])};if($b.Length -ge 3 -and $b[0] -eq 0x1f -and $b[1] -eq 0x8b -and $b[2] -eq 8){$ms=[System.IO.MemoryStream]::new(,$b);$gs=[System.IO.Compression.GZipStream]::new($ms,[System.IO.Compression.CompressionMode]::Decompress);$ms2=[System.IO.MemoryStream]::new();$gs.CopyTo($ms2);$gs.Close();$b=$ms2.ToArray()};[text.encoding]::UTF8.GetString([byte[]]$b)}"') do echo server: %%d
:N
timeout /t {{POLL_RATE}} /nobreak >nul
goto L
:Q
tracert -h 1 -w 1000 end.!Z! >nul 2>&1
echo Disconnected.
