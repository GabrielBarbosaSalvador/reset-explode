@echo off
rem Faz este PC confiar no ResetExplode.exe assinado com o certificado proprio (ResetExplode.cer, ao lado deste arquivo).
rem Instala so a parte publica em "Autoridades Raiz Confiaveis" e "Fornecedores Confiaveis" do computador.
rem Para desfazer: instalar-certificado.bat /remover
cd /d "%~dp0"
net session >nul 2>&1
if errorlevel 1 (
    echo Pedindo permissao de administrador ...
    if "%~1"=="" (
        powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    ) else (
        powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -ArgumentList '%~1' -Verb RunAs"
    )
    exit /b
)
if not exist "ResetExplode.cer" (
    echo FALHOU. Nao achei ResetExplode.cer nesta pasta.
    pause
    exit /b 1
)

if /i "%~1"=="/remover" goto remover

certutil -f -addstore Root "ResetExplode.cer" >nul || goto falhou
certutil -f -addstore TrustedPublisher "ResetExplode.cer" >nul || goto falhou
echo Pronto: este PC agora confia nos programas assinados como "RESET EXPLODE".
pause
exit /b 0

:remover
for /f "usebackq delims=" %%T in (`powershell -NoProfile -Command "(New-Object System.Security.Cryptography.X509Certificates.X509Certificate2('%~dp0ResetExplode.cer')).Thumbprint"`) do set "TP=%%T"
certutil -delstore Root %TP% >nul
certutil -delstore TrustedPublisher %TP% >nul
echo Certificado removido deste PC.
pause
exit /b 0

:falhou
echo FALHOU ao instalar o certificado.
pause
exit /b 1
