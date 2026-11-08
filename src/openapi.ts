export const openapi = {
  openapi: '3.0.3',
  info: { title: 'Authentication API', version: '1.0.0', description: 'API para cadastro, autenticação e perfil de usuários.' },
  servers: [{ url: '/' }],
  components: {
    securitySchemes: { bearerAuth: { type: 'http', scheme: 'bearer', bearerFormat: 'JWT' } },
    schemas: {
      RegisterRequest: { type: 'object', additionalProperties: false, required: ['name', 'email', 'password'], properties: { name: { type: 'string', minLength: 2, maxLength: 100 }, email: { type: 'string', format: 'email', maxLength: 254 }, password: { type: 'string', minLength: 12, format: 'password', description: 'Deve conter letras maiúsculas, minúsculas e número.' } } },
      LoginRequest: { type: 'object', additionalProperties: false, required: ['email', 'password'], properties: { email: { type: 'string', format: 'email' }, password: { type: 'string', format: 'password' } } },
      RefreshRequest: { type: 'object', additionalProperties: false, required: ['refreshToken'], properties: { refreshToken: { type: 'string' } } },
      User: { type: 'object', required: ['id', 'name', 'email'], properties: { id: { type: 'string' }, name: { type: 'string' }, email: { type: 'string', format: 'email' } } },
      Tokens: { type: 'object', required: ['accessToken', 'refreshToken'], properties: { accessToken: { type: 'string' }, refreshToken: { type: 'string' } } },
      AccessToken: { type: 'object', required: ['accessToken'], properties: { accessToken: { type: 'string' } } },
      Error: { type: 'object', required: ['error', 'message'], properties: { error: { type: 'string' }, message: { type: 'string' } } }
    }
  },
  paths: {
    '/auth/register': { post: { operationId: 'registerUser', summary: 'Cadastra um usuário', requestBody: { required: true, content: { 'application/json': { schema: { $ref: '#/components/schemas/RegisterRequest' } } } }, responses: { '201': { description: 'Usuário criado', content: { 'application/json': { schema: { $ref: '#/components/schemas/User' } } } }, '400': { description: 'Entrada inválida', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } }, '409': { description: 'E-mail já cadastrado', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } }, '429': { description: 'Muitas tentativas', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } } } } },
    '/auth/login': { post: { operationId: 'authenticateUser', summary: 'Autentica um usuário', requestBody: { required: true, content: { 'application/json': { schema: { $ref: '#/components/schemas/LoginRequest' } } } }, responses: { '200': { description: 'Tokens emitidos', content: { 'application/json': { schema: { $ref: '#/components/schemas/Tokens' } } } }, '400': { description: 'Entrada inválida', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } }, '401': { description: 'Credenciais inválidas', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } }, '429': { description: 'Muitas tentativas', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } } } } },
    '/auth/refresh': { post: { operationId: 'refreshAccessToken', summary: 'Emite novo access token', requestBody: { required: true, content: { 'application/json': { schema: { $ref: '#/components/schemas/RefreshRequest' } } } }, responses: { '200': { description: 'Novo access token', content: { 'application/json': { schema: { $ref: '#/components/schemas/AccessToken' } } } }, '400': { description: 'Entrada inválida', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } }, '401': { description: 'Refresh token inválido', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } } } } },
    '/auth/logout': { post: { operationId: 'logoutUserSession', summary: 'Encerra a sessão atual', security: [{ bearerAuth: [] }], responses: { '204': { description: 'Sessão encerrada' }, '401': { description: 'Não autenticado', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } } } } },
    '/users/me': { get: { operationId: 'getAuthenticatedUserProfile', summary: 'Consulta o próprio perfil', security: [{ bearerAuth: [] }], responses: { '200': { description: 'Perfil do usuário autenticado', content: { 'application/json': { schema: { $ref: '#/components/schemas/User' } } } }, '401': { description: 'Não autenticado', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } } } } }
  }
} as const;
