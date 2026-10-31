/**
 * Suíte complementar ao OWASP ZAP para RS01, RS02, RS04, RS05, RS06 e RS07.
 * RS03 (dependências) pertence ao SCA e não é avaliada neste script.
 * Descobre operações e schemas exclusivamente pelo OpenAPI em /openapi.json.
 * Não presume nomes de rotas, operationId ou biblioteca de documentação.
 *
 * Node.js 20+ (ESM). Saída: DAST_OUTPUT_DIR/dast-tests.json
 */
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';

const BASE = (process.env.DAST_BASE_URL || 'http://127.0.0.1:3000').replace(/\/$/, '');
const OUT = process.env.DAST_OUTPUT_DIR || 'evidence/dast';
const OPENAPI = `${BASE}/openapi.json`;
const METHODS = ['get', 'post', 'put', 'patch', 'delete', 'head', 'options'];
const results = [];
const MAX_OPERATIONS = 60;
const MAX_BODY_TESTS = 25;
const random = () => crypto.randomUUID();
const is2xx = n => n >= 200 && n < 300;
const json = value => JSON.stringify(value);

function add(rs, id, outcome, detail, extra = {}) {
  results.push({ requirement: rs, id, outcome, detail, ...extra });
  console.log(`[DAST][${rs}] ${id}: ${outcome} — ${detail}`);
}

function curl(method, url, body) {
  const args = ['--silent', '--show-error', '--max-time', '20', '--request', method,
    '--header', 'Accept: application/json', '--write-out', '\n__STATUS__:%{http_code}', url];
  if (body !== undefined) args.splice(args.length - 1, 0,
    '--header', 'Content-Type: application/json', '--data-binary', json(body));
  const raw = execFileSync('curl', args, { encoding: 'utf8', timeout: 25000, maxBuffer: 5 * 1024 * 1024 });
  const marker = '\n__STATUS__:';
  const at = raw.lastIndexOf(marker);
  if (at < 0) throw new Error(`Resposta HTTP sem status: ${method} ${url}`);
  const text = raw.slice(0, at);
  const status = Number(raw.slice(at + marker.length).trim());
  if (!Number.isInteger(status) || status <= 0) throw new Error(`Status HTTP inválido: ${method} ${url}`);
  return { status, text, data: (() => { try { return JSON.parse(text); } catch { return null; } })() };
}

function resolvePath(template) {
  return template.replace(/\{([^}]+)\}/g, (_, name) => encodeURIComponent(`dast-${name}-${random()}`));
}

function schemaSample(schema, invalid = false, spec = {}) {
  if (!schema || typeof schema !== 'object') return invalid ? null : {};
  if (schema.$ref) {
    const key = schema.$ref.split('/').pop();
    return schemaSample(spec.components?.schemas?.[key] || {}, invalid, spec);
  }
  if (schema.type === 'object' || schema.properties) {
    const out = {};
    for (const [key, child] of Object.entries(schema.properties || {})) {
      out[key] = schemaSample(child, false, spec);
    }
    if (invalid) {
      const required = schema.required?.[0] || Object.keys(schema.properties || {})[0];
      if (required) out[required] = { deliberately: 'invalid-type' };
      else out.__dast_unexpected = { deliberately: 'unexpected-field' };
    }
    return out;
  }
  if (schema.type === 'array') return invalid ? 'not-an-array' : [];
  if (schema.type === 'integer' || schema.type === 'number') return invalid ? 'not-a-number' : 1;
  if (schema.type === 'boolean') return invalid ? 'not-a-boolean' : true;
  if (schema.type === 'string') {
    if (invalid) return 123456;
    if (schema.format === 'email') return `dast-${random()}@example.invalid`;
    if (/password|secret|token/i.test(schema.title || '')) return `Dast-${random()}!`;
    return 'dast-test-value';
  }
  return invalid ? { invalid: true } : null;
}

function operationBody(op, spec, invalid = false) {
  const content = op.requestBody?.content || {};
  const media = content['application/json'];
  return media?.schema ? schemaSample(media.schema, invalid, spec) : undefined;
}

function securityRequired(op, spec) {
  return Array.isArray(op.security) ? op.security.length > 0
    : Array.isArray(spec.security) && spec.security.length > 0;
}

function inspectSensitive(value, prefix = '') {
  if (!value || typeof value !== 'object') return null;
  for (const [key, child] of Object.entries(value)) {
    if (/^(password|passwd|passwordhash|password_hash|hashedpassword|password_digest|credentialhash|credential_hash)$/i.test(key)
      && child !== null && child !== '' && child !== false) return `${prefix}${key}`;
    const nested = inspectSensitive(child, `${prefix}${key}.`);
    if (nested) return nested;
  }
  return null;
}

function leaksInternals(text) {
  return /\bat\s+\w+\s*\([^\n]*:\d+:\d+\)|\b(stack trace|syntaxerror|referenceerror|typeormerror|prisma\.[a-z]+error)\b|node_modules\/|\bselect\s+.+\s+from\s+|\b(insert into|update\s+\w+\s+set)\b/i.test(text || '');
}

function classifyStatus(status) {
  return status >= 500 ? 'ERROR' : 'NOT_EVALUATED';
}

function main() {
  fs.mkdirSync(OUT, { recursive: true });
  const specResponse = curl('GET', OPENAPI);
  if (!is2xx(specResponse.status) || !specResponse.data?.paths || typeof specResponse.data.paths !== 'object') {
    throw new Error(`OpenAPI indisponível ou inválido em ${OPENAPI} (HTTP ${specResponse.status}).`);
  }
  const spec = specResponse.data;
  fs.writeFileSync(path.join(OUT, 'openapi.json'), JSON.stringify(spec, null, 2));

  const operations = [];
  for (const [route, pathItem] of Object.entries(spec.paths)) {
    for (const method of METHODS) {
      const op = pathItem?.[method];
      if (op && typeof op === 'object') operations.push({ route, method: method.toUpperCase(), op, pathItem });
    }
  }
  const selected = operations.slice(0, MAX_OPERATIONS);
  add('GERAL', 'openapi-discovery', 'PASS', `${operations.length} operações descobertas; ${selected.length} serão avaliadas pelo limite de execução.`, { totalOperations: operations.length });

  // RS01: testa operações declaradas como protegidas sem fornecer credenciais.
  const protectedOps = selected.filter(x => securityRequired(x.op, spec) && ['GET', 'HEAD', 'OPTIONS'].includes(x.method));
  if (!protectedOps.length) add('RS01', 'protected-operations', 'NOT_EVALUATED', 'OpenAPI não declarou operações com requisito de segurança; não é possível presumir quais recursos exigem autenticação.');
  for (const x of protectedOps) {
    try {
      const route = resolvePath(x.route);
      const response = curl(x.method, BASE + route);
      if ([401, 403].includes(response.status)) add('RS01', `${x.method} ${x.route} unauthenticated`, 'PASS', 'Operação declarada como protegida recusou acesso sem credenciais.', { httpStatus: response.status });
      else if (is2xx(response.status)) add('RS01', `${x.method} ${x.route} unauthenticated`, 'FAIL', 'Operação declarada como protegida aceitou acesso sem credenciais.', { httpStatus: response.status });
      else add('RS01', `${x.method} ${x.route} unauthenticated`, classifyStatus(response.status), `Resposta não conclusiva para controle de acesso.`, { httpStatus: response.status });
      if (leaksInternals(response.text)) add('RS02/RS07', `${x.method} ${x.route} error-disclosure`, 'FAIL', 'Resposta expôs padrão associado a detalhes internos.', { httpStatus: response.status });
      const sensitive = inspectSensitive(response.data);
      if (sensitive) add('RS04', `${x.method} ${x.route} credential-exposure`, 'FAIL', `Resposta contém campo sensível: ${sensitive}.`, { httpStatus: response.status });
    } catch (e) { add('RS01', `${x.method} ${x.route}`, 'ERROR', e.message); }
  }

  // RS02, RS04 e RS07: inspeciona respostas de operações documentadas, sem autenticação.
  for (const x of selected.filter(v => ['GET', 'HEAD', 'OPTIONS'].includes(v.method))) {
    try {
      const route = resolvePath(x.route);
      const response = curl(x.method, BASE + route);
      const runtimeSecrets = [process.env.JWT_ACCESS_SECRET, process.env.JWT_REFRESH_SECRET].filter(Boolean);
      if (runtimeSecrets.some(secret => response.text.includes(secret))) add('RS02', `${x.method} ${x.route} runtime-secret`, 'FAIL', 'Resposta reproduziu segredo de autenticação configurado no ambiente.', { httpStatus: response.status });
      const sensitive = inspectSensitive(response.data);
      if (sensitive) add('RS04', `${x.method} ${x.route} credential-exposure`, 'FAIL', `Campo sensível exposto: ${sensitive}.`, { httpStatus: response.status });
      if (leaksInternals(response.text)) add('RS02/RS07', `${x.method} ${x.route} internal-error-disclosure`, 'FAIL', 'Resposta contém stack trace, caminho interno, erro de implementação ou detalhe de consulta.', { httpStatus: response.status });
      if (response.status >= 500) add('RS07', `${x.method} ${x.route} server-error`, 'FAIL', 'Operação documentada produziu resposta HTTP 5xx durante a sondagem sem autenticação.', { httpStatus: response.status });
    } catch (e) { add('RS02/RS04/RS07', `${x.method} ${x.route}`, 'ERROR', e.message); }
  }

  // RS05: envia corpo JSON deliberadamente incompatível com o schema documentado.
  let bodyTests = 0;
  for (const x of selected.filter(v => ['POST', 'PUT', 'PATCH'].includes(v.method) && v.op.requestBody).slice(0, MAX_BODY_TESTS)) {
    try {
      const body = operationBody(x.op, spec, true);
      if (body === undefined) { add('RS05', `${x.method} ${x.route} invalid-input`, 'NOT_EVALUATED', 'O OpenAPI não documenta corpo application/json para esta operação.'); continue; }
      const response = curl(x.method, BASE + resolvePath(x.route), body);
      if ([400, 415, 422].includes(response.status)) add('RS05', `${x.method} ${x.route} invalid-input`, 'PASS', 'Entrada incompatível com o schema foi rejeitada.', { httpStatus: response.status });
      else if (is2xx(response.status)) add('RS05', `${x.method} ${x.route} invalid-input`, 'FAIL', 'A API aceitou entrada deliberadamente incompatível com o schema.', { httpStatus: response.status });
      else add('RS05', `${x.method} ${x.route} invalid-input`, classifyStatus(response.status), 'Resposta não conclusiva para validação de entrada.', { httpStatus: response.status });
      if (leaksInternals(response.text)) add('RS07', `${x.method} ${x.route} invalid-input-error`, 'FAIL', 'Entrada inválida provocou exposição de detalhes internos.', { httpStatus: response.status });
      bodyTests++;
    } catch (e) { add('RS05', `${x.method} ${x.route} invalid-input`, 'ERROR', e.message); }
  }
  if (!bodyTests) add('RS05', 'invalid-input', 'NOT_EVALUATED', 'OpenAPI não forneceu corpos de requisição JSON adequados para sondagem segura.');

  // RS06: identifica operações candidatas por metadados OpenAPI, sem fixar rotas.
  const authCandidates = selected.filter(x => {
    const meta = `${x.op.operationId || ''} ${x.op.summary || ''} ${x.op.description || ''} ${(x.op.tags || []).join(' ')}`;
    const schemaText = json(x.op.requestBody || {});
    return /login|sign.?in|authenticate|token|authenticat/i.test(meta) && /password|credential/i.test(schemaText);
  });
  if (!authCandidates.length) {
    add('RS06', 'authentication-operation', 'NOT_EVALUATED', 'OpenAPI não identificou inequivocamente operação de autenticação com credencial; não foram inventadas rotas ou payloads.');
  } else {
    for (const candidate of authCandidates.slice(0, 2)) {
      const emailField = (obj, prefix = '') => {
        if (!obj || typeof obj !== 'object') return null;
        for (const [key, value] of Object.entries(obj)) {
          if (/^(email|username|user)$/i.test(key)) return `${prefix}${key}`;
          if (value && typeof value === 'object') { const found = emailField(value, `${prefix}${key}.`); if (found) return found; }
        }
        return null;
      };
      const basePayload = operationBody(candidate.op, spec, false);
      if (!basePayload || typeof basePayload !== 'object' || Array.isArray(basePayload)) {
        add('RS06', `${candidate.method} ${candidate.route} repeated-invalid-login`, 'NOT_EVALUATED', 'O schema da operação candidata não permite construir um corpo de credenciais com segurança.');
        continue;
      }
      const emailKey = emailField(basePayload);
      const passwordKey = Object.keys(basePayload).find(k => /password|passwd/i.test(k));
      if (!emailKey || !passwordKey) {
        add('RS06', `${candidate.method} ${candidate.route} repeated-invalid-login`, 'NOT_EVALUATED', 'Não foi possível identificar os campos de usuário e senha no corpo documentado.');
        continue;
      }
      const attemptResponses = [];
      try {
        for (let i = 0; i < 5; i++) {
          const payload = structuredClone(basePayload);
          payload[emailKey] = `dast-invalid-${random()}@example.invalid`;
          payload[passwordKey] = `Invalid-${random()}!`;
          attemptResponses.push(curl(candidate.method, BASE + resolvePath(candidate.route), payload));
        }
        if (attemptResponses.some(r => [423, 429].includes(r.status))) {
          add('RS06', `${candidate.method} ${candidate.route} repeated-invalid-login`, 'PASS', 'A API aplicou resposta de bloqueio ou limitação durante cinco tentativas inválidas.', { httpStatuses: attemptResponses.map(r => r.status) });
        } else if (attemptResponses.some(r => is2xx(r.status))) {
          add('RS06', `${candidate.method} ${candidate.route} repeated-invalid-login`, 'FAIL', 'Uma tentativa com credenciais sintéticas inválidas foi aceita.', { httpStatuses: attemptResponses.map(r => r.status) });
        } else if (attemptResponses.some(r => r.status >= 500)) {
          add('RS06', `${candidate.method} ${candidate.route} repeated-invalid-login`, 'ERROR', 'A API apresentou erro de servidor durante tentativas inválidas.', { httpStatuses: attemptResponses.map(r => r.status) });
        } else {
          add('RS06', `${candidate.method} ${candidate.route} repeated-invalid-login`, 'NOT_EVALUATED', 'As tentativas foram recusadas, mas a especificação não define limite ou política de bloqueio; não é possível concluir se há proteção contra automação.', { httpStatuses: attemptResponses.map(r => r.status) });
        }
      } catch (e) { add('RS06', `${candidate.method} ${candidate.route} repeated-invalid-login`, 'ERROR', e.message); }
    }
  }

  // RS02: segredo de ambiente não deve aparecer em respostas ou mensagens.
  const secrets = [process.env.JWT_ACCESS_SECRET, process.env.JWT_REFRESH_SECRET].filter(Boolean);
  if (secrets.length) {
    const observed = results.some(r => r.detail && secrets.some(secret => r.detail.includes(secret)));
    add('RS02', 'runtime-secret-disclosure', observed ? 'FAIL' : 'PASS', observed ? 'Segredo de execução apareceu nas evidências de resposta.' : 'Segredos de execução não foram encontrados nos textos analisados.');
  } else add('RS02', 'runtime-secret-disclosure', 'NOT_EVALUATED', 'Segredos de execução não foram disponibilizados ao script para comparação.');

  const counts = Object.fromEntries(['PASS', 'FAIL', 'NOT_EVALUATED', 'ERROR'].map(k => [k, results.filter(x => x.outcome === k).length]));
  const report = { schemaVersion: 2, completed: true, source: '/openapi.json', excludedRequirements: ['RS03'], requirements: ['RS01', 'RS02', 'RS04', 'RS05', 'RS06', 'RS07'], totalOperations: operations.length, testedOperations: selected.length, counts, tests: results };
  fs.writeFileSync(path.join(OUT, 'dast-tests.json'), JSON.stringify(report, null, 2));
  console.log(`[DAST] Concluído: ${JSON.stringify(counts)}`);
}

try { main(); }
catch (error) {
  fs.mkdirSync(OUT, { recursive: true });
  const report = { schemaVersion: 2, completed: false, excludedRequirements: ['RS03'], counts: { PASS: 0, FAIL: 0, NOT_EVALUATED: 0, ERROR: 1 }, tests: [{ requirement: 'GERAL', id: 'executor', outcome: 'ERROR', detail: error.message }] };
  fs.writeFileSync(path.join(OUT, 'dast-tests.json'), JSON.stringify(report, null, 2));
  console.error(`[DAST] Falha: ${error.stack || error}`);
  process.exitCode = 1;
}
