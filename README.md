# API de Autenticação

API REST em Express e TypeScript, com Prisma e SQLite. Implementa cadastro, login, renovação de token, logout revogável e consulta do perfil do próprio usuário.

## Instalação e execução local

1. Instale o Node.js 22 ou superior e execute `npm install`.
2. Copie `.env.example` para `.env` e substitua os segredos JWT por valores longos e aleatórios.
3. Crie o banco e aplique as migrações: `npx prisma migrate dev`.
4. Inicie em desenvolvimento: `npm run dev`.

A API atende em `http://localhost:3000` por padrão. Para compilar e executar a versão de produção, use `npm run build` e `npm start`.

## Docker

Defina `JWT_ACCESS_SECRET` e `JWT_REFRESH_SECRET` no ambiente e execute:

```bash
docker compose up --build
```

O volume `sqlite-data` mantém o banco SQLite entre reinicializações. O container aplica as migrações antes de iniciar a API.

## Endpoints

- `POST /auth/register` — corpo: `name`, `email`, `password` (mínimo de 8 caracteres); retorna o usuário criado.
- `POST /auth/login` — corpo: `email`, `password`; retorna `accessToken` e `refreshToken`.
- `POST /auth/refresh` — corpo: `refreshToken`; retorna novo `accessToken`.
- `POST /auth/logout` — requer `Authorization: Bearer <accessToken>`; revoga a sessão, inclusive para o token de acesso atual.
- `GET /users/me` — requer bearer token; retorna somente o perfil da identidade autenticada.

## OpenAPI

A especificação está disponível em [http://localhost:3000/openapi.json](http://localhost:3000/openapi.json). Ela descreve todas as operações, os códigos de resposta e a autenticação Bearer JWT.

## Verificações executadas

- `npm install`: concluído em 2 de novembro de 2026; o `npm audit` informou 10 vulnerabilidades transitivas (3 moderadas, 5 altas e 2 críticas), sem aplicação automática de correções potencialmente incompatíveis.
- `npm run build`: concluído com sucesso.
- `npm test`: concluído com sucesso (1 arquivo e 1 teste). Cobre cadastro, autenticação, perfil, renovação e revogação de sessão.

## Limitações de verificação

`npx prisma generate` foi concluído com sucesso. O `schema-engine` do Prisma retornou erro sem detalhes ao executar `npx prisma migrate dev --name init` neste ambiente Windows, apesar da migração SQL ter sido disponibilizada em `prisma/migrations`. A aplicação da migração local não pôde ser confirmada neste ambiente; execute `npx prisma migrate dev` localmente ou inicie o container para aplicá-la.
