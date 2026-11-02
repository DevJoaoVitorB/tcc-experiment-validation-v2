#!/usr/bin/env node

/**
 * Prepara uma sessão de teste para a varredura DAST.
 *
 * Contrato esperado na especificação OpenAPI:
 * - operationId registerUser: cadastro com campos semanticamente
 *   identificáveis como nome, e-mail e senha;
 * - operationId loginUser: autenticação com e-mail e senha;
 * - operationId getCurrentUser: consulta do próprio perfil;
 * - resposta do login contendo accessToken;
 * - operação getCurrentUser protegida por esquema HTTP Bearer.
 *
 * Os caminhos HTTP, métodos e schemas são descobertos no OpenAPI.
 * O script não grava senha ou token nas evidências.
 */

import { randomBytes, randomUUID } from 'node:crypto';
import { appendFileSync, mkdirSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';

const [openApiFile, baseUrlArgument, evidenceFile] = process.argv.slice(2);

function fail(message) {
  throw new Error(message);
}

function readJsonFile(file) {
  try {
    return JSON.parse(awaitlessRead(file));
  } catch (error) {
    fail(`Não foi possível ler o OpenAPI em ${file}: ${error.message}`);
  }
}

// Separado para manter a leitura síncrona e não depender de bibliotecas externas.
import { readFileSync } from 'node:fs';
function awaitlessRead(file) {
  return readFileSync(file, 'utf8');
}

function resolvePointer(document, reference) {
  if (!reference.startsWith('#/')) {
    fail(`Referência OpenAPI externa não suportada pelo script: ${reference}`);
  }

  return reference
    .slice(2)
    .split('/')
    .map((part) => part.replaceAll('~1', '/').replaceAll('~0', '~'))
    .reduce((value, part) => value?.[part], document);
}

function dereference(document, value, seen = new Set()) {
  if (!value || typeof value !== 'object') return value;
  if (Array.isArray(value)) {
    return value.map((item) => dereference(document, item, seen));
  }

  if (typeof value.$ref === 'string') {
    if (seen.has(value.$ref)) fail(`Referência circular no OpenAPI: ${value.$ref}`);
    const nextSeen = new Set(seen);
    nextSeen.add(value.$ref);
    const target = resolvePointer(document, value.$ref);
    if (!target) fail(`Referência não encontrada no OpenAPI: ${value.$ref}`);
    return dereference(document, target, nextSeen);
  }

  const result = {};
  for (const [key, child] of Object.entries(value)) {
    result[key] = dereference(document, child, seen);
  }
  return result;
}

const HTTP_METHODS = new Set(['get', 'post', 'put', 'patch', 'delete', 'options', 'head', 'trace']);

function findOperation(document, operationId) {
  const matches = [];
  for (const [path, pathItemRaw] of Object.entries(document.paths ?? {})) {
    const pathItem = dereference(document, pathItemRaw);
    for (const [method, operation] of Object.entries(pathItem ?? {})) {
      if (HTTP_METHODS.has(method.toLowerCase()) && operation?.operationId === operationId) {
        matches.push({ path, method: method.toUpperCase(), operation, pathItem });
      }
    }
  }

  if (matches.length !== 1) {
    fail(`Esperada exatamente uma operação com operationId '${operationId}', encontradas: ${matches.length}.`);
  }

  return matches[0];
}

function getOperationUrl(document, operationInfo, baseUrl) {
  const { path, operation, pathItem } = operationInfo;
  const server = operation.servers?.[0] ?? pathItem.servers?.[0] ?? document.servers?.[0];
  let serverBase = new URL(baseUrl);

  if (server?.url) {
    if (server.url.includes('{')) {
      fail(`O servidor OpenAPI contém variáveis não resolvidas: ${server.url}`);
    }
    const declaredServer = new URL(server.url, baseUrl);
    const configuredBase = new URL(baseUrl);
    // Mantém o prefixo de caminho documentado, mas usa a origem alcançável
    // pelo runner do pipeline (DAST_BASE_URL).
    declaredServer.protocol = configuredBase.protocol;
    declaredServer.host = configuredBase.host;
    serverBase = declaredServer;
  }

  const serverPrefix = serverBase.pathname.replace(/\/+$/, '');
  const normalizedPath = path.replace(/^\//, '');
  const url = new URL(`${serverPrefix}/${normalizedPath}`, serverBase.origin);

  const requiredPathParameters = (operation.parameters ?? [])
    .concat(operationInfo.pathItem.parameters ?? [])
    .filter((parameter) => parameter.in === 'path' && parameter.required !== false);

  if (requiredPathParameters.length > 0 || url.pathname.includes('{')) {
    fail(`A operação ${operation.operation.operationId} possui parâmetros de caminho obrigatórios; o script não os presume.`);
  }

  return url;
}

function jsonRequestSchema(document, operationInfo) {
  const requestBodyRaw = operationInfo.operation.requestBody;
  if (!requestBodyRaw) fail(`A operação ${operationInfo.operation.operationId} não documenta requestBody.`);

  const requestBody = dereference(document, requestBodyRaw);
  const content = requestBody.content ?? {};
  const mediaType = Object.keys(content).find(
    (type) => type.toLowerCase() === 'application/json' || type.toLowerCase().endsWith('+json'),
  );

  if (!mediaType) {
    fail(`A operação ${operationInfo.operation.operationId} não documenta corpo JSON.`);
  }

  return { mediaType, schema: dereference(document, content[mediaType].schema ?? {}) };
}

function collectSchemaProperties(schema) {
  const properties = { ...(schema.properties ?? {}) };
  for (const part of schema.allOf ?? []) {
    Object.assign(properties, collectSchemaProperties(part));
  }
  return properties;
}

function normalizeName(value) {
  return value.normalize('NFD').replace(/[\u0300-\u036f]/g, '').toLowerCase().replace(/[^a-z0-9]/g, '');
}

function findProperty(properties, aliases, semantic, operationId) {
  const aliasSet = new Set(aliases.map(normalizeName));
  const matches = Object.keys(properties).filter((key) => aliasSet.has(normalizeName(key)));
  if (matches.length !== 1) {
    fail(`Não foi possível identificar unicamente o campo semântico '${semantic}' no schema de ${operationId}.`);
  }
  return matches[0];
}

function buildPayload(document, operationInfo, values, requiredSemantics) {
  const { mediaType, schema } = jsonRequestSchema(document, operationInfo);
  const properties = collectSchemaProperties(schema);
  const payload = {};

  const aliases = {
    name: ['name', 'nome', 'fullName', 'nomeCompleto'],
    email: ['email', 'e-mail', 'mail'],
    password: ['password', 'senha'],
  };

  for (const semantic of requiredSemantics) {
    const propertyName = findProperty(properties, aliases[semantic], semantic, operationInfo.operation.operationId);
    payload[propertyName] = values[semantic];
  }

  const required = schema.required ?? [];
  const missingRequired = required.filter((property) => !(property in payload));
  if (missingRequired.length > 0) {
    fail(`O schema de ${operationInfo.operation.operationId} exige campos adicionais não previstos no teste: ${missingRequired.join(', ')}.`);
  }

  return { mediaType, payload };
}

async function sendJsonRequest(url, method, payload, mediaType = 'application/json', headers = {}) {
  const response = await fetch(url, {
    method,
    headers: {
      Accept: 'application/json',
      ...(payload === undefined ? {} : { 'Content-Type': mediaType }),
      ...headers,
    },
    ...(payload === undefined ? {} : { body: JSON.stringify(payload) }),
    signal: AbortSignal.timeout(15000),
  });

  let body = null;
  const responseText = await response.text();
  if (responseText) {
    try {
      body = JSON.parse(responseText);
    } catch {
      body = null;
    }
  }

  return { response, body };
}

function findAccessToken(value) {
  if (!value || typeof value !== 'object') return undefined;
  if (Array.isArray(value)) {
    for (const item of value) {
      const token = findAccessToken(item);
      if (token) return token;
    }
    return undefined;
  }

  for (const [key, child] of Object.entries(value)) {
    if (normalizeName(key) === 'accesstoken' && typeof child === 'string' && child.length > 0) {
      return child;
    }
  }
  for (const child of Object.values(value)) {
    const token = findAccessToken(child);
    if (token) return token;
  }
  return undefined;
}

function assertSuccessful(label, response) {
  if (!response.ok) fail(`${label} falhou: HTTP ${response.status}. Verifique a implementação e o contrato OpenAPI.`);
}

function assertBearerSecurity(document, operationInfo) {
  const security = Object.hasOwn(operationInfo.operation, 'security')
    ? operationInfo.operation.security
    : document.security;

  if (!Array.isArray(security) || security.length === 0) {
    fail('A operação getCurrentUser não declara requisito de segurança no OpenAPI.');
  }

  const schemes = document.components?.securitySchemes ?? {};
  const bearerSchemeNames = Object.entries(schemes)
    .filter(([, scheme]) => scheme?.type === 'http' && String(scheme.scheme).toLowerCase() === 'bearer')
    .map(([name]) => name);

  const isBearerProtected = security.some((requirement) =>
    bearerSchemeNames.some((name) => Object.hasOwn(requirement, name)),
  );

  if (!isBearerProtected) {
    fail('A operação getCurrentUser não está vinculada a um esquema HTTP Bearer no OpenAPI.');
  }
}

async function main() {
  if (!openApiFile || !baseUrlArgument || !evidenceFile) {
    fail('Uso: node prepare-dast-auth.mjs <openapi.json> <base-url> <authentication-evidence.json>');
  }

  const document = readJsonFile(resolve(openApiFile));
  const baseUrl = new URL(baseUrlArgument);
  const register = findOperation(document, 'registerUser');
  const login = findOperation(document, 'loginUser');
  const profile = findOperation(document, 'getCurrentUser');
  assertBearerSecurity(document, profile);

  const uniqueId = randomUUID();
  const testUser = {
    name: 'DAST Automated User',
    email: `dast-${uniqueId}@example.test`,
    password: `Dast!Aa1${randomBytes(18).toString('hex')}`,
  };

  const registration = buildPayload(document, register, testUser, ['name', 'email', 'password']);
  const registrationUrl = getOperationUrl(document, register, baseUrl);
  const registrationResult = await sendJsonRequest(
    registrationUrl,
    register.method,
    registration.payload,
    registration.mediaType,
  );
  assertSuccessful('Cadastro do usuário de teste', registrationResult.response);

  const loginPayload = buildPayload(document, login, testUser, ['email', 'password']);
  const loginUrl = getOperationUrl(document, login, baseUrl);
  const loginResult = await sendJsonRequest(loginUrl, login.method, loginPayload.payload, loginPayload.mediaType);
  assertSuccessful('Autenticação do usuário de teste', loginResult.response);

  const accessToken = findAccessToken(loginResult.body);
  if (!accessToken) fail('A resposta do login não contém um campo accessToken identificável.');

  const profileUrl = getOperationUrl(document, profile, baseUrl);
  const profileResult = await sendJsonRequest(profileUrl, profile.method, undefined, undefined, {
    Authorization: `Bearer ${accessToken}`,
  });
  assertSuccessful('Validação do acesso autenticado ao perfil', profileResult.response);

  const envFile = process.env.GITHUB_ENV || process.env.DAST_ENV_FILE;
  if (!envFile) fail('GITHUB_ENV não está definido. Para execução local, defina DAST_ENV_FILE.');

  const headerValue = `Bearer ${accessToken}`;
  const headerSite = process.env.DAST_ZAP_AUTH_HEADER_SITE || 'host.docker.internal';
  // Solicita ao GitHub Actions que mascare o token e o valor completo do cabeçalho.
  if (process.env.GITHUB_ACTIONS === 'true') {
    process.stdout.write(`::add-mask::${accessToken}\n`);
    process.stdout.write(`::add-mask::${headerValue}\n`);
  }

  appendFileSync(envFile, [
    `ZAP_AUTH_HEADER_VALUE=${headerValue}`,
    'ZAP_AUTH_HEADER=Authorization',
    `ZAP_AUTH_HEADER_SITE=${headerSite}`,
    '',
  ].join('\n'));

  const evidence = {
    authentication_preparation: 'success',
    user_registration: { operationId: 'registerUser', method: register.method, status: registrationResult.response.status },
    user_login: { operationId: 'loginUser', method: login.method, status: loginResult.response.status },
    access_token_extracted: true,
    authenticated_profile_request: {
      operationId: 'getCurrentUser',
      method: profile.method,
      status: profileResult.response.status,
    },
    zap_header_prepared: true,
    zap_header_name: 'Authorization',
    zap_header_site: headerSite,
    secrets_written_to_evidence: false,
  };

  mkdirSync(dirname(resolve(evidenceFile)), { recursive: true });
  writeFileSync(resolve(evidenceFile), `${JSON.stringify(evidence, null, 2)}\n`, { mode: 0o600 });
  process.stdout.write('Sessão DAST preparada e validada. Token disponibilizado ao próximo passo do pipeline.\n');
}

main().catch((error) => {
  process.stderr.write(`::error::${error.message}\n`);
  process.exitCode = 1;
});
