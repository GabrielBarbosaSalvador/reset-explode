# Assinatura digital do ResetExplode.exe

O `publicar.bat` e o GitHub Actions assinam o `.exe` automaticamente quando há um certificado configurado.
Sem certificado, o `.exe` sai sem assinatura (como antes) e o publicar só avisa.

## Qual certificado usar

| Opção | Custo | Resolve em quais PCs |
|---|---|---|
| **Certificado próprio** (`criar-certificado.ps1`) | grátis | Só nos PCs onde você rodar `instalar-certificado.bat` |
| **Certificado comprado / serviço de assinatura** (Certum Open Source, SignPath Foundation, Azure Artifact Signing, Sectigo...) | de grátis (projetos open source aprovados) a ~US$ 200–400/ano | Em qualquer PC (o SmartScreen pode avisar no começo, até o programa ganhar reputação) |

Certificado próprio **não** tira o aviso do SmartScreen nem o bloqueio do *Controle Inteligente de Aplicativos*
em PCs que não instalaram o `.cer`: o Windows só confia em autoridades certificadoras do programa da Microsoft.

## Certificado próprio (seus PCs)

1. Uma vez, no PC onde você compila:
   ```
   powershell -NoProfile -ExecutionPolicy Bypass -File assinatura\criar-certificado.ps1
   ```
   Cria `CN=RESET EXPLODE` em *Certificados – Usuário Atual\Pessoal* (chave não exportável) e gera `assinatura\ResetExplode.cer`.
2. Rode `assinatura\instalar-certificado.bat` (pede administrador) neste PC e em cada PC que vai usar o programa.
   O `publicar.bat` já copia o `.cer` e o `instalar-certificado.bat` para `ResetExplode-dist`.
   Para desfazer: `instalar-certificado.bat /remover`.
3. Rode `publicar.bat` normalmente.

Instalar o `.cer` faz o PC confiar em **qualquer programa** assinado com essa chave; ela é limitada a assinatura de código,
mas guarde-a bem (não exporte sem necessidade).

## Certificado comprado (token USB ou nuvem)

Desde 2023 a chave desses certificados fica num token/HSM, não num `.pfx`. Instale o software do fornecedor
(ex.: SimplySign da Certum) para o certificado aparecer em *Usuário Atual\Pessoal* e informe a impressão digital:
```
setx RESET_CERT_THUMBPRINT "AB12...EF"
```
O `publicar.bat` passa a assinar com ele. Nesse caso não é preciso distribuir `.cer` nem `instalar-certificado.bat`.

## GitHub Actions

O workflow assina se existirem os secrets `SIGN_PFX_BASE64` e `SIGN_PFX_SENHA`
(gere com `criar-certificado.ps1 -ExportarPfx`; o `.pfx` é ignorado pelo git). Serviços como SignPath e
Azure Artifact Signing têm uma action própria, que substituiria o passo "Assinar".

## Conferir

```
powershell -Command "Get-AuthenticodeSignature ..\ResetExplode-dist\ResetExplode.exe | Format-List"
```
`Valid` = assinado e confiável neste PC; `UnknownError` = assinado, mas este PC ainda não confia no certificado.
