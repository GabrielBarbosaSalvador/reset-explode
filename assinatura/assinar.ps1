# Assina o ResetExplode.exe (Authenticode) com carimbo de data/hora.
# Uso: powershell -NoProfile -ExecutionPolicy Bypass -File assinatura\assinar.ps1 -Arquivo ..\ResetExplode-dist\ResetExplode.exe
#
# De onde vem o certificado (o primeiro que existir):
#   1. RESET_SIGN_PFX (+ RESET_SIGN_PFX_SENHA): caminho de um .pfx (usado no GitHub Actions)
#   2. RESET_CERT_THUMBPRINT: impressão digital de um certificado do repositório do Windows
#      (ex.: certificado comprado em token USB / nuvem, que aparece em "Certificados - Usuário Atual")
#   3. O certificado criado por criar-certificado.ps1 (CN=RESET EXPLODE) no repositório do usuário
# Sem certificado, avisa e sai com código 2 (o .exe fica sem assinatura, mas o publicar continua).
param(
    [Parameter(Mandatory = $true)][string]$Arquivo,
    [string]$Timestamp = 'http://timestamp.digicert.com'
)
$ErrorActionPreference = 'Stop'

function Achar-Certificado {
    if ($env:RESET_SIGN_PFX) {
        $senha = if ($env:RESET_SIGN_PFX_SENHA) { $env:RESET_SIGN_PFX_SENHA } else { '' }
        return New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
            (Resolve-Path $env:RESET_SIGN_PFX).Path, $senha,
            [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
    }
    $todos = @(Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert) + @(Get-ChildItem Cert:\LocalMachine\My -CodeSigningCert -ErrorAction SilentlyContinue)
    $validos = $todos | Where-Object { $_.HasPrivateKey -and $_.NotAfter -gt (Get-Date) }
    if ($env:RESET_CERT_THUMBPRINT) {
        $t = $env:RESET_CERT_THUMBPRINT -replace '\s', ''
        return $validos | Where-Object { $_.Thumbprint -eq $t } | Select-Object -First 1
    }
    return $validos | Where-Object { $_.Subject -eq 'CN=RESET EXPLODE' } | Sort-Object NotAfter -Descending | Select-Object -First 1
}

$cert = Achar-Certificado
if (-not $cert) {
    Write-Host 'AVISO: nenhum certificado de assinatura encontrado; o .exe vai SEM assinatura.'
    Write-Host '       Rode assinatura\criar-certificado.ps1 uma vez (veja assinatura\LEIA-ME.md).'
    exit 2
}

Write-Host "Assinando com: $($cert.Subject) (valido ate $($cert.NotAfter.ToString('dd/MM/yyyy')))"
# Se o servidor de carimbo falhar (sem internet), assina sem carimbo: vale ate o certificado vencer.
try {
    $r = Set-AuthenticodeSignature -FilePath $Arquivo -Certificate $cert -HashAlgorithm SHA256 -TimestampServer $Timestamp
} catch {
    Write-Host "AVISO: carimbo de data/hora indisponivel ($($_.Exception.Message)); assinando sem ele."
    $r = Set-AuthenticodeSignature -FilePath $Arquivo -Certificate $cert -HashAlgorithm SHA256
}
# UnknownError = assinado, mas a raiz nao e confiavel neste PC (certificado proprio ainda nao instalado)
if ($r.Status -ne 'Valid' -and $r.Status -ne 'UnknownError') {
    Write-Host "FALHOU a assinatura: $($r.Status) - $($r.StatusMessage)"
    exit 1
}
Write-Host "Assinado: $($r.Status) - $($r.StatusMessage)"
exit 0
