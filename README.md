# ModStation

Plataforma independente para descoberta, publicação e distribuição de conteúdo de Minecraft Java e Bedrock. O repositório contém uma API FastAPI, interface responsiva em HTML/CSS/JavaScript, persistência SQLAlchemy com PostgreSQL/SQLite e migrações Alembic.

## Inicialização rápida validada no Codespace

```bash
cp .env.example .env
python -c 'import secrets; print(secrets.token_urlsafe(48))'
```

Coloque o valor gerado em `SECRET_KEY`, aplique as migrações e inicie:

```bash
set -a
source .env
set +a
alembic upgrade head
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

O repositório também inclui `.devcontainer/devcontainer.json` e `.vscode/tasks.json`. Na criação do Codespace, `.devcontainer/setup.sh` preserva um `.env` existente, gera `SECRET_KEY` se estiver vazio e instala as dependências.

## Executar no GitHub Codespaces

Python 3.11+ e pip são necessários. Docker Compose é opcional para usar PostgreSQL e ClamAV locais.

### Inicialização rápida com SQLite

```bash
cp .env.example .env
python -c 'import secrets; print(secrets.token_urlsafe(48))'
```

Configure o valor gerado em `SECRET_KEY` no `.env`, depois carregue as variáveis e instale:

```bash
set -a
source .env
set +a
python -m pip install -r requirements.txt
alembic upgrade head
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

Abra a porta 8000 no Codespaces. SQLite e a interface funcionam sem serviços externos. **Sem ClamAV e YARA funcionais, os uploads permanecem inconclusivos e não podem ser publicados ou baixados.** Isso é intencional: o modo de desenvolvimento não simula uma aprovação.

### PostgreSQL e ClamAV locais

Preencha as variáveis PostgreSQL do `.env.example` no `.env`, inicie os serviços e configure a URL do banco:

```bash
docker compose up -d postgres clamav
export DATABASE_URL="postgresql+psycopg://${POSTGRES_USER}:${POSTGRES_PASSWORD}@127.0.0.1:5432/${POSTGRES_DB}"
export CLAMD_HOST=127.0.0.1
export CLAMD_PORT=3310
alembic upgrade head
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

O ClamAV precisa concluir a atualização de assinaturas antes de responder a análises. Erros, timeout, ausência de regras YARA ou falha da integração externa deixam a análise **inconclusiva**, nunca aprovada.

### Primeiro administrador

Com as mesmas variáveis de ambiente da aplicação e as migrações aplicadas:

```bash
python -m app.cli create-admin --email admin@example.com --username modadmin
```

A senha é solicitada sem eco no terminal. A criação inicial de administradores não está exposta por endpoint HTTP. Um administrador pode gerenciar papéis de usuário, desenvolvedor e moderador; a promoção de novos administradores é deliberadamente restrita ao procedimento operacional.

## Configuração

| Variável | Uso |
| --- | --- |
| `DATABASE_URL` | SQLAlchemy. SQLite local: `sqlite:///./data/modstation.db`; PostgreSQL: `postgresql+psycopg://...`. |
| `SECRET_KEY` | Chave HMAC usada para armazenar digests de tokens. Obrigatória em produção, com pelo menos 32 caracteres aleatórios. |
| `APP_ENV` | Use `production` para cookies `Secure`, HSTS e validação estrita da configuração. |
| `COOKIE_SECURE` | Ativa o atributo `Secure` dos cookies; deve ser `true` sob HTTPS. |
| `MAX_UPLOAD_BYTES` | Limite de upload; padrão 20 MiB. Capas PNG são limitadas a 5 MiB. |
| `STORAGE_ROOT`, `QUARANTINE_ROOT` | Diretórios privados para arquivos aprovados e pendentes/rejeitados. Não os exponha por servidor estático. |
| `CLAMD_HOST`, `CLAMD_PORT` | Serviço ClamAV/clamd pelo protocolo TCP INSTREAM. |
| `YARA_RULES_PATH` | Arquivo de regras YARA compilável; o repositório fornece um conjunto inicial pequeno em `security/rules.yar`. |
| `VIRUSTOTAL_API_KEY` | Opcional. Consulta somente o hash SHA-256 pela API v3; o arquivo não é enviado. Hash sem relatório conhecido torna a análise inconclusiva. |
| `REQUIRE_EMAIL_VERIFICATION` | Em produção deve ser `true`; impede acesso de desenvolvedor até verificação. |
| `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_FROM` | Entrega de verificação e recuperação de senha via SMTP com STARTTLS. Use um segredo do ambiente, não o versionamento. |
| `ALLOWED_ORIGINS` | Lista separada por vírgulas das origens públicas autorizadas para CORS e origem de requisições mutáveis. |
| `API_URL` | URL pública HTTPS do backend usada pela configuração de CSP da API. |
| `COOKIE_SAME_SITE` | `lax` para mesmo domínio; `none` com HTTPS para frontend GitHub Pages em domínio cruzado. |
| `OBJECT_STORAGE_*` | Bucket, endpoint, região e credenciais de armazenamento privado S3 compatível. |

Para produção, configure PostgreSQL, HTTPS e cookies seguros, SMTP, regras YARA revisadas, ClamAV atualizado, backups, armazenamento privado durável, proxy confiável e controles de taxa compartilhados entre instâncias. No modo local (`REQUIRE_EMAIL_VERIFICATION=false`), contas ainda não verificadas podem solicitar perfil de desenvolvedor para permitir testes sem SMTP; em produção a aplicação exige verificação e SMTP. O limite padrão de upload é 20 MiB; ao aumentá-lo, ajuste também `StreamMaxLength` e limites de varredura do ClamAV. O limitador embutido é por processo e não substitui proteção distribuída na borda.

## Publicação gratuita

Os arquivos de implantação gratuitos disponíveis no repositório são:

- `Dockerfile` e `Procfile`: executam migrações e iniciam a API.
- `render.yaml`: modelo de serviço web para uma hospedagem Docker.
- `docker-compose.yml`: PostgreSQL, ClamAV e aplicação em um servidor ou Codespaces.
- `.github/workflows/pages.yml`: publica `web/` no GitHub Pages.

### Frontend no GitHub Pages

1. Em **Settings → Pages**, escolha **GitHub Actions** como origem.
2. Em **Settings → Secrets and variables → Actions → Variables**, crie `MODSTATION_API_URL` com a URL HTTPS pública do backend, sem barra final.
3. Mantenha a branch principal como `main` e envie o repositório.

O workflow lê essa variável e configura o meta de API no HTML. Nenhuma chave é enviada ao frontend.

### Backend e banco

Use uma hospedagem gratuita compatível com Docker ou FastAPI para o backend e PostgreSQL gratuito externo. Configure pelo menos:

```text
DATABASE_URL
SECRET_KEY
APP_ENV=production
COOKIE_SECURE=true
COOKIE_SAME_SITE=none
ALLOWED_ORIGINS=https://seu-usuario.github.io
API_URL=https://seu-backend.exemplo
REQUIRE_EMAIL_VERIFICATION=true
SMTP_HOST=...
SMTP_PORT=587
SMTP_USERNAME=...
SMTP_PASSWORD=...
SMTP_FROM=...
```

Para configurar o backend no mesmo domínio do frontend, `COOKIE_SAME_SITE=lax` pode ser usado e `ALLOWED_ORIGINS` pode conter a origem completa. GitHub Pages e o backend em outro domínio exigem `None`, HTTPS e `COOKIE_SECURE=true`.

### Armazenamento gratuito

O projeto suporta diretórios privados locais e armazenamento S3 compatível. Para R2 ou outro provedor gratuito com API S3 compatível, configure:

```text
OBJECT_STORAGE_BUCKET
OBJECT_STORAGE_ENDPOINT
OBJECT_STORAGE_REGION=auto
OBJECT_STORAGE_ACCESS_KEY
OBJECT_STORAGE_SECRET_KEY
```

O backend grava arquivos em quarentena, move apenas para armazenamento aprovado após análise e entrega bytes privados pela API. Credenciais S3 ficam exclusivamente no backend.

### ClamAV e YARA

O modo de produção deve manter ClamAV disponível em rede privada ou por serviço separado. `CLAMD_HOST` e `CLAMD_PORT` apontam para `clamd`. YARA usa `YARA_RULES_PATH`; a configuração fornecida é apenas inicial e deve ser revisada pela operação. Arquivos não são executados no servidor principal.

Para iniciar ClamAV no Codespace ou em Docker local:

```bash
docker compose --env-file .env up -d clamav
docker compose logs -f clamav
docker compose ps clamav
```

O serviço só libera arquivos após responder exatamente `stream: OK`. Respostas ausentes, malformadas, timeout ou erro de rede deixam o upload inconclusivo. Uma detecção do EICAR é registrada como ameaça e bloqueada.

Hospedagens gratuitas com filesystem ou instâncias temporárias não garantem persistência. Use PostgreSQL persistente e armazenamento S3 compatível. Hospedagens gratuitas podem acordar/encerrar processos, limitar memória, upload, tempo de análise e quantidade de horas: nessas condições, a plataforma continua segura, mas pode ficar indisponível ou inconclusiva.

## Funcionalidades disponíveis

- Catálogo paginado e busca por nome, categoria, edição e versão; ordenação por atualização, downloads e avaliação. Somente conteúdo publicado aparece.
- Cadastro e login com Argon2id, sessões opacas em cookies `HttpOnly`, logout, token CSRF, verificação de e-mail e recuperação por token enviado por SMTP.
- Configurações de conta com troca de senha autenticada, revogação das demais sessões e reenvio de verificação.
- Perfis públicos de desenvolvedor; pedidos de publicação, versões, arquivos privados, estado de análise e submissão para moderação.
- MTS com pontuação explicável: base 10; até +18,25 por antiguidade (0,05/dia, máximo de 365 dias); até +40 por publicações aprovadas (2 cada, máximo de 20); +5 por identidade verificada; −4 por denúncia confirmada e −12 por violação confirmada (cada fator limitado a 10). Pontuação limitada a 0–100, sem privilégios de segurança.
- MSE com SHA-256, validação de ZIP/formatos, proteção contra traversal, limite de entradas/tamanho/razão de compressão, ClamAV, YARA, quarentena privada, estados persistidos, histórico, reanálise administrativa e revisão humana restrita de alertas YARA quando os outros controles aplicáveis estiverem limpos. A aprovação MSE não publica automaticamente: moderação de conteúdo e revisão humana de versões também são necessárias.
- Download autenticado opcionalmente e autorizado no servidor; exige simultaneamente conteúdo publicado e arquivo aprovado. Downloads, favoritos, comentários, respostas, avaliações, denúncias e notificações são persistidos.
- Moderação de conteúdo e denúncias, papéis controlados no backend, desativação de contas e trilha de auditoria administrativa.
- Respostas de erro explícitas, limitação de requisições por processo, validação de entrada, cabeçalhos de segurança e armazenamento fora do diretório estático.

## API e testes

Em ambiente de desenvolvimento, a documentação OpenAPI fica em `/docs`. A rota `/api/health` verifica a conexão atual com o banco.

```bash
pytest -q
```

Os testes usam um banco SQLite isolado e verificam autenticação, proteção CSRF, validação e bloqueio de publicação/download quando os scanners não estão disponíveis. Para verificar a migração de ponta a ponta em SQLite:

```bash
DATABASE_URL=sqlite:///./data/migration-check.db alembic upgrade head
```

## Limitações e operação segura

- A análise é estática e depende das versões, assinaturas, configuração e regras instaladas. Não promete detectar todas as ameaças. Nenhum arquivo enviado é executado.
- A integração VirusTotal consulta reputação de hash; não envia automaticamente arquivos. Um hash desconhecido ou erro do serviço não autoriza publicação.
- A entrega de e-mail depende de SMTP. Solicitações de recuperação retornam indisponibilidade explícita quando não há SMTP configurado.
- Capas PNG são validadas estruturalmente, têm metadados auxiliares removidos, passam pelo MSE e por revisão humana antes de serem exibidas. Outros formatos de imagem, armazenamento de mídia externo e análise dinâmica isolada ainda não estão implementados.
- O armazenamento atual usa diretórios privados locais. Em produção, use volume privado durável, controle de acesso e cópias de segurança; nunca sirva diretamente `storage` ou `quarantine`.
- A pontuação MTS é indicativa, tem critérios transparentes e não substitui revisão humana, antivírus nem controle de permissões.
