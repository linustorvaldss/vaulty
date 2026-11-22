# vaulty

Gestor de secretos multi-tenant. Los valores se guardan en **AWS Secrets Manager** cifrados con **KMS**; la base de datos (Postgres) solo guarda metadatos. Incluye API REST, CLI (`vaulty`) y login con Google, GitHub, GitLab, OAuth 2.0/OIDC genérico y email.

## MVP

| Feature | Estado |
|---|---|
| Auth: Google, GitHub, GitLab, OAuth2/OIDC genérico, email + contraseña | ✅ |
| Multi-tenancy: workspace personal por usuario + organizaciones con roles | ✅ |
| Cloud: conectar la cuenta AWS del tenant (assume role + external id + KMS propio) | ✅ |
| Proyectos y entornos (development, staging, production por defecto, + custom) | ✅ |
| CRUD de secretos (valor en Secrets Manager/KMS, versionado) | ✅ |
| CLI: login con token de acceso, `pull`, `run` (inyecta env vars), `push`, `set/get/unset` | ✅ |
| Links para compartir un entorno (expiración, máx. vistas, passphrase, revocables) | ✅ |
| Subir archivos y procesar cada secreto individualmente: `.env`, JSON, `settings.json`/`appsettings.json` (JSONC), XML (`web.config`), YAML | ✅ |

## Arquitectura (hexagonal)

```
cmd/
  vaulty-api/        composition root: conecta adaptadores con el núcleo
  vaulty/            CLI
internal/
  domain/            entidades, reglas y errores (sin dependencias externas)
  port/              interfaces que necesita el núcleo (repos, SecretVault, OAuthProvider, ...)
  service/           casos de uso (auth, tenants, proyectos, secretos, import, shares)
  parser/            parseo/render de .env, JSON(C), XML, YAML (puro, sin I/O)
  adapter/
    http/            adaptador de entrada: API REST (Gin)
    store/           persistencia GORM (Postgres en prod, SQLite en dev/tests)
    vault/awssm/     SecretVault → AWS Secrets Manager + KMS (+ STS AssumeRole por tenant)
    vault/local/     SecretVault → AES-256-GCM en la DB (solo desarrollo)
    oauth/           Google, GitHub, GitLab, OIDC genérico
    security/        bcrypt + JWT
  client/            cliente HTTP usado por la CLI
  config/            configuración por variables de entorno
```

Las dependencias apuntan hacia adentro: `adapter → service → port/domain`. El núcleo no importa Gin, GORM ni el SDK de AWS.

### Cómo se guardan los secretos

- Cada secreto de Vaulty = un secreto de Secrets Manager: `<prefix>/<tenant>/<project>/<env>/<secret-id>`, con tags `vaulty:*`.
- Cifrado con la CMK de KMS de la plataforma (`AWS_KMS_KEY_ID`) o la del tenant si conectó su cuenta.
- Si el tenant conectó AWS, Vaulty asume su rol (`sts:AssumeRole` con `ExternalId`) y los secretos viven **en su cuenta**.
- Lecturas masivas (`pull`, `run`, shares) usan `BatchGetSecretValue` (20 por llamada).
- Costo: Secrets Manager cobra por secreto/mes; se eligió 1:1 por versionado, permisos y auditoría por secreto.

## Arranque local

```bash
cp .env.example .env
go run ./cmd/vaulty-api          # SQLite + vault local, sin AWS
```

Producción: `ENV=production`, `DATABASE_URL=postgres://...`, `VAULT_DRIVER=awssm`, `JWT_SECRET` (≥32 caracteres) y credenciales AWS (rol de IAM de la instancia/tarea).

```bash
go test ./...
go build -o bin/vaulty ./cmd/vaulty
```

## API (`/api/v1`)

Autenticación: `Authorization: Bearer <jwt de sesión | token vty_...>`. Tenant: header `X-Tenant-ID` (id o slug); por defecto el workspace personal. Los tokens de acceso quedan atados a su workspace.

| Método | Ruta | Descripción |
|---|---|---|
| POST | `/auth/register`, `/auth/login` | email + contraseña → `{token, user}` |
| GET | `/auth/providers` | proveedores habilitados |
| GET | `/auth/oauth/{google\|github\|gitlab\|oidc}/start?redirect_uri=` | inicia OAuth |
| GET | `/auth/oauth/{provider}/callback` | redirige a `redirect_uri#token=...` |
| GET | `/me`, `/tenants` · POST `/tenants` | perfil, workspaces, crear organización |
| GET/POST/DELETE | `/tenant/members[/{userID}]` | miembros (owner/admin/member/viewer) |
| GET/PUT/DELETE | `/cloud/aws` · POST `/cloud/aws/verify` | conexión AWS del tenant |
| GET/POST | `/tokens` · DELETE `/tokens/{id}` | tokens de acceso para CLI/CI |
| GET/POST | `/projects` · GET/PATCH/DELETE `/projects/{p}` | proyectos |
| GET/POST | `/projects/{p}/environments` · DELETE `.../{env}` | entornos |
| GET/POST | `.../environments/{env}/secrets` (`?reveal=true`) | listar/crear |
| GET/PUT/DELETE | `.../secrets/{KEY}` | leer/upsert/borrar |
| POST | `.../secrets/import?format=&strategy=overwrite\|skip\|fail&dry_run=&normalize=&separator=&prefix=` | subir archivo (multipart `file` o body) |
| GET | `.../secrets/export?format=dotenv\|json\|yaml\|shell` | descargar |
| GET/POST | `.../environments/{env}/shares` · DELETE `/shares/{id}` | links compartibles |
| GET/POST | `/shared/{token}` (público, `?format=`, header `X-Share-Passphrase`) | abrir link |

## CLI

```bash
vaulty login --token vty_xxx --api https://api.vaulty.dev
vaulty link -p shop-api -e development     # crea .vaulty.json
vaulty push .env                           # o settings.json, web.config, config.yaml
vaulty pull -o .env                        # o -f json|yaml|shell
vaulty run -- npm run dev                  # inyecta los secretos como variables de entorno
vaulty set STRIPE_KEY=sk_test_123
vaulty share --keys STRIPE_KEY --hours 2 --max-views 1
```

En CI: `VAULTY_TOKEN`, `VAULTY_API_URL`, `VAULTY_PROJECT`, `VAULTY_ENV`.

## AWS

**Cuenta de la plataforma** (rol de la instancia que corre la API):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    { "Effect": "Allow",
      "Action": ["secretsmanager:CreateSecret","secretsmanager:PutSecretValue","secretsmanager:GetSecretValue",
                 "secretsmanager:BatchGetSecretValue","secretsmanager:DeleteSecret","secretsmanager:TagResource",
                 "secretsmanager:ListSecrets"],
      "Resource": "*" },
    { "Effect": "Allow", "Action": ["kms:Encrypt","kms:Decrypt","kms:GenerateDataKey","kms:DescribeKey"],
      "Resource": "arn:aws:kms:REGION:ACCOUNT:key/KEY_ID" },
    { "Effect": "Allow", "Action": "sts:AssumeRole", "Resource": "arn:aws:iam::*:role/vaulty-*" }
  ]
}
```

**Cuenta del tenant**: crear un rol `vaulty-access` con los permisos de Secrets Manager/KMS de arriba y esta trust policy (el `external_id` lo devuelve `PUT /cloud/aws`); luego `POST /cloud/aws/verify`.

```json
{ "Effect": "Allow", "Principal": { "AWS": "arn:aws:iam::PLATFORM_ACCOUNT:root" },
  "Action": "sts:AssumeRole", "Condition": { "StringEquals": { "sts:ExternalId": "vaulty-..." } } }
```

## Pendiente / fuera del MVP

- Verificación de email y reset de contraseña (requiere proveedor de email).
- Invitaciones por email (hoy se agrega a usuarios ya registrados).
- Login de la CLI vía navegador (device flow); hoy es con token.
- Log de auditoría y rotación automática.
- Rate limiting compartido (hoy es en memoria por instancia).
- Migraciones versionadas (hoy `AutoMigrate`).
