# Sigma JSON Schema — proveniência

```text
Ficheiro   sigma-detection-rule-schema.json
Origem     https://github.com/SigmaHQ/sigma-specification
Caminho    json-schema/sigma-detection-rule-schema.json
Commit     ba9251aa834b   (2026-06-09)
Obtido     2026-09-07, via API do GitHub
Tamanho    8.922 bytes
SHA-256    EB95DDB1BC2503145A6E84511E38990F... (32 primeiros caracteres)
Draft      https://json-schema.org/draft/2020-12/schema#
```

Versionado aqui de propósito: uma validação que depende da rede não é reproduzível, e o
resultado do CI passaria a depender do dia em que corre. Actualizar é uma acção deliberada,
com o commit da especificação registado acima.

## Licenciamento

A especificação do Sigma e o **conteúdo de regras** da SigmaHQ têm termos diferentes. Este
ficheiro é a especificação — schema, não detecção. Nenhuma regra da SigmaHQ foi copiada para
este repositório. Ver `docs/LICENSING.md`.

## O que este schema valida, e o que não valida

```text
VALIDA      forma da regra: campos, tipos, formatos, valores permitidos em level e status
NAO VALIDA  se o pySigma compila a regra para um backend
NAO VALIDA  se a regra deteta alguma coisa
NAO VALIDA  as convencoes do repositorio SigmaHQ (nome de ficheiro, ordem de tags, etc.)
```

Campos obrigatórios pelo schema: apenas `title`, `logsource`, `detection`. Este projecto
exige mais do que isso no seu próprio gate — incluindo `falsepositives` não vazio.
