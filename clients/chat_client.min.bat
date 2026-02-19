@echo off&setlocal enabledelayedexpansion&set Z={{DOMAIN_ZONE}}
:L
set /p "M=you: "&if /i "!M!"=="/quit" goto Q
for /f %%h in ('powershell -nop -c "$k=@({{KEY_CSV}});$m=[text.encoding]::UTF8.GetBytes('%M%');-join($m|%%{(($_-bxor$k[$i++%%4]).ToString('x2'))})"') do set H=%%h
tracert -h 1 -w 1000 !H!.tx.!Z!>nul 2>&1&set R=
for /f "tokens=*" %%a in ('tracert -w 2000 rx.!Z!^|findstr /i "!Z!"^|findstr /v /i "end. empty. rx. Tracing"') do (for %%b in (%%a) do (echo %%b|findstr /i "!Z!">nul&&(set "W=%%b"&set "W=!W:.%Z%=!"&for /f "delims=" %%x in ('powershell -nop -c "$w='!W!';($w-split'\.'|?{$_.Length%%2 -eq 0 -and $_ -match ''^[0-9a-f]+$''})-join''"') do set R=!R!%%x)))
if "!R!"=="" goto L
for /f %%d in ('powershell -nop -c "$k=@({{KEY_CSV}});$h='%R%';$b=for($i=0;$i-lt$h.length;$i+=2){[byte]([convert]::ToByte($h.Substring($i,2),16)-bxor$k[($i/2)%%4])};[text.encoding]::UTF8.GetString([byte[]]$b)"') do echo ^< %%d
timeout /t {{POLL_RATE}} /nobreak >nul&goto L
:Q
tracert -h 1 -w 1000 end.!Z!>nul 2>&1
