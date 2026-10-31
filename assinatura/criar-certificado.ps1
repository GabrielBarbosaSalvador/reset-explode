# Cria (uma vez) o certificado proprio de assinatura do RESET EXPLODE neste PC.
# Uso: powershell -NoProfile -ExecutionPolicy Bypass -File assinatura\criar-certificado.ps1 [-ExportarPfx]
#
# - A chave privada fica so no repositorio do usuario atual (Cert:\CurrentUser\My) e NAO pode ser exportada,
#   a nao ser que use -ExportarPfx (para colocar no GitHub Actions; guarde o .pfx em local seguro e NUNCA no git).
# - Gera assinatura\ResetExplode.cer (so a parte publica), que vai junto do .exe para os outros PCs confiarem nele.
# - O certificado so serve para assinar programas (EKU "Code Signing"), nao para sites nem e-mail.
param([switch]$ExportarPfx)
$ErrorActionPreference = 'Stop'
$pasta = $PSScriptRoot

$cert = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert |
    Where-Object { $_.Subject -eq 'CN=RESET EXPLODE' -and $_.NotAfter -gt (Get-Date) } |
    Sort-Object NotAfter -Descending | Select-Object -First 1
if ($cert) {
    Write-Host "Ja existe um certificado: $($cert.Thumbprint) (valido ate $($cert.NotAfter.ToString('dd/MM/yyyy')))"
} else {
    $cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject 'CN=RESET EXPLODE' `
        -FriendlyName 'RESET EXPLODE - assinatura de codigo' `
        -KeyAlgorithm RSA -KeyLength 3072 -HashAlgorithm SHA256 `
        -KeyExportPolicy $(if ($ExportarPfx) { 'Exportable' } else { 'NonExportable' }) `
        -CertStoreLocation Cert:\CurrentUser\My -NotAfter (Get-Date).AddYears(5)
    Write-Host "Certificado criado: $($cert.Thumbprint) (valido ate $($cert.NotAfter.ToString('dd/MM/yyyy')))"
}

Export-Certificate -Cert $cert -FilePath (Join-Path $pasta 'ResetExplode.cer') -Type CERT | Out-Null
Write-Host "Parte publica salva em $(Join-Path $pasta 'ResetExplode.cer')"

if ($ExportarPfx) {
    $senha = Read-Host 'Senha para o .pfx' -AsSecureString
    $pfx = Join-Path $pasta 'ResetExplode.pfx'
    Export-PfxCertificate -Cert $cert -FilePath $pfx -Password $senha | Out-Null
    Write-Host "Chave privada salva em $pfx (ignorado pelo git). Para o GitHub Actions:"
    Write-Host '  secret SIGN_PFX_BASE64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes("assinatura\ResetExplode.pfx"))'
    Write-Host '  secret SIGN_PFX_SENHA  = a senha acima'
    Write-Host 'Depois apague o .pfx deste PC ou guarde-o fora da pasta do projeto.'
}

Write-Host ''
Write-Host 'Agora rode assinatura\instalar-certificado.bat (como administrador) para este PC confiar no programa.'
