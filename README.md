# API de autenticação

API REST em Express e TypeScript com Prisma e SQLite. Ela implementa cadastro, login, renovação de access token, encerramento de sessão e consulta do próprio perfil.

## Requisitos

- Node.js 24 ou superior
- npm
- Docker (opcional, para execução em container)

## Configuração e execução local

1. Instale as dependências e copie a configuração de exemplo:

   ```powershell
   npm install
   Copy-Item .env.example .env
   ```

2. Em `.env`, substitua `JWT_ACCESS_SECRET` e `JWT_REFRESH_SECRET` por segredos distintos, aleatórios e com ao menos 32 caracteres.

3. Gere o cliente Prisma, aplique as migrações e inicie a API:

   ```powershell
   npm run prisma:generate
   npx prisma migrate deploy
   npm run dev
   ```

Em desenvolvimento, a API fica disponível em `http://localhost:3000`. Para compilar e iniciar a versão compilada, execute `npm run build` e `npm start`.

## Docker

Crie a imagem e execute o container informando os segredos no ambiente:

```powershell
docker build -t auth-api .
docker run --rm -p 3000:3000 --env-file .env -e DATABASE_URL="file:/data/auth.db" -v auth-api-data:/data auth-api
```

O volume nomeado preserva o SQLite e as migrações são aplicadas automaticamente na inicialização.

## Endpoints

- `POST /auth/register` — cria usuário com `name`, `email` e `password`.
- `POST /auth/login` — devolve `accessToken` e `refreshToken` para credenciais válidas.
- `POST /auth/refresh` — recebe `refreshToken` e devolve um novo `accessToken`.
- `POST /auth/logout` — requer `Authorization: Bearer <accessToken>` e revoga a sessão atual.
- `GET /users/me` — requer Bearer token e devolve somente o perfil do usuário autenticado.

Senhas devem ter entre 12 e 128 caracteres, incluindo letras maiúsculas, minúsculas e números. Access tokens expiram em 15 minutos; refresh tokens, em 7 dias. O logout persiste a revogação, por isso ambos deixam de autorizar ações após seu uso.

## OpenAPI

A especificação fiel à API está disponível em `GET /openapi.json`, por exemplo: `http://localhost:3000/openapi.json`. Ela documenta os esquemas de entrada, respostas, erros e autenticação Bearer das rotas protegidas.

## Segurança

As senhas são armazenadas somente como hashes bcrypt com custo 12. As entradas são validadas estritamente, erros não expõem detalhes internos, o login não diferencia e-mail inexistente de senha inválida e cadastro/login possuem limitação simples de 10 tentativas por IP a cada 15 minutos. A sessão é consultada no banco em toda rota protegida, permitindo invalidar imediatamente os access tokens no logout.

## Verificações realizadas

Em 8 de novembro de 2026, foram executados com sucesso:

```powershell
npm run check
npm test
npm run build
npm audit --omit=dev
```

Resultados: a checagem TypeScript e a compilação concluíram sem erros; os 2 testes passaram, cobrindo o ciclo de cadastro, login, perfil, refresh, logout/revogação e a rota OpenAPI; a auditoria reportou 0 vulnerabilidades conhecidas.

O build e a execução com Docker não foram realizados porque o executável `docker` não estava disponível no ambiente de verificação.
