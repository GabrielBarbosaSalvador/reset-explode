@echo off
rem Gera o RESET EXPLODE pronto para levar a outro PC (nao precisa instalar o .NET la).
rem Saida: ..\ResetExplode-dist\ResetExplode.exe + LEIA-ME.txt
rem Sempre recompila do zero a partir do codigo atual desta pasta.
cd /d "%~dp0"
set "EXE=..\ResetExplode-dist\ResetExplode.exe"

echo Fechando o ResetExplode se estiver aberto (inclusive na bandeja) ...
taskkill /f /im ResetExplode.exe >nul 2>&1
call :rodando
if errorlevel 1 goto esperar_arquivo
rem O app roda como administrador, entao um taskkill comum recebe "acesso negado".
echo O ResetExplode esta rodando como administrador. Confirme o pedido do Windows para fecha-lo ...
powershell -NoProfile -Command "try { Start-Process taskkill -ArgumentList '/f','/im','ResetExplode.exe' -Verb RunAs -WindowStyle Hidden -Wait } catch { exit 1 }"

:esperar_arquivo
rem Espera ate 15s o processo sair e o Windows liberar o .exe.
set /a TENTATIVAS=0
:loop_arquivo
if not exist "%EXE%" goto publicar
(type nul >> "%EXE%") 2>nul && goto publicar
set /a TENTATIVAS+=1
if %TENTATIVAS% geq 15 (
    echo.
    echo FALHOU. O arquivo "%EXE%" esta em uso por outro programa.
    echo Feche o ResetExplode pela bandeja ^(perto do relogio^) e rode de novo.
    echo O .exe antigo NAO foi atualizado.
    pause
    exit /b 1
)
ping -n 2 127.0.0.1 >nul
goto loop_arquivo

:publicar
echo Gerando ResetExplode.exe a partir do codigo atual ...
rmdir /s /q obj\Release >nul 2>&1
dotnet publish -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -p:DebugType=None -o "..\ResetExplode-dist" -nologo -v q
if errorlevel 1 (
    echo.
    echo FALHOU. Veja os erros acima. O .exe antigo NAO foi atualizado.
    pause
    exit /b 1
)
copy /y "LEIA-ME.txt" "..\ResetExplode-dist\LEIA-ME.txt" >nul
echo.
echo Pronto: %~dp0..\ResetExplode-dist
for %%F in ("%EXE%") do echo Arquivo gerado em %%~tF (confira se e de agora^)
pause
exit /b 0

rem errorlevel 0 = ResetExplode.exe ainda esta rodando
:rodando
tasklist /fi "imagename eq ResetExplode.exe" /nh 2>nul | find /i "ResetExplode.exe" >nul
exit /b %errorlevel%
