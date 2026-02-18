# vaulty

MVP API service for managing users, projects, and secrets in-memory using a simple hexagonal architecture (ports/adapters).

## Run

```bash
PORT=8080 go run .
```

## Endpoints

- `GET /health`
- `GET /users`
- `POST /users`
- `GET /projects`
- `POST /projects`
- `GET /secrets` (optional `?project_id=UUID`)
- `POST /secrets`

## Example

```bash
curl -X POST http://localhost:8080/users \
  -H "Content-Type: application/json" \
  -d '{"name":"Ada","email":"ada@example.com"}'
```
