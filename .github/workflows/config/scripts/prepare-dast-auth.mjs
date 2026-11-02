#!/usr/bin/env node

/**
 * Prepara uma sessão de teste para a varredura DAST.
 *
 * As operações são descobertas dinamicamente a partir da especificação OpenAPI.
 * Nenhum operationId ou caminho específico é exigido.
 *
 * Critérios:
 * - Cadastro: POST com campos semanticamente equivalentes a nome, e-mail e senha.
 * - Login: POST com e-mail e senha, sem campo de nome.
 * - Perfil: GET protegido por esquema HTTP Bearer.
 *
 * A seleção considera também caminho, operationId, summary e description.
 * Em caso de ambiguidade, o script falha e lista as operações candidatas.
 * Senhas e tokens não são gravados nas evidências.
 */

import { randomBytes, randomUUID } from 'node:crypto';
import {
    appendFileSync,
    mkdirSync,
    readFileSync,
    writeFileSync,
} from 'node:fs';
import { dirname, resolve } from 'node:path';

const [openApiFile, baseUrlArgument, evidenceFile] = process.argv.slice(2);

function fail(message) {
    throw new Error(message);
}

function readJsonFile(file) {
    try {
        return JSON.parse(readFileSync(file, 'utf8'));
    } catch (error) {
        fail(`Não foi possível ler o OpenAPI em ${file}: ${error.message}`);
    }
}

function resolvePointer(document, reference) {
    if (!reference.startsWith('#/')) {
        fail(
            `Referência OpenAPI externa não suportada pelo script: ${reference}`,
        );
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
        if (seen.has(value.$ref)) {
            fail(`Referência circular no OpenAPI: ${value.$ref}`);
        }

        const nextSeen = new Set(seen);
        nextSeen.add(value.$ref);

        const target = resolvePointer(document, value.$ref);
        if (!target)
            fail(`Referência não encontrada no OpenAPI: ${value.$ref}`);

        return dereference(document, target, nextSeen);
    }

    const result = {};
    for (const [key, child] of Object.entries(value)) {
        result[key] = dereference(document, child, seen);
    }

    return result;
}

const HTTP_METHODS = new Set([
    'get',
    'post',
    'put',
    'patch',
    'delete',
    'options',
    'head',
    'trace',
]);

const FIELD_ALIASES = {
    name: ['name', 'nome', 'fullName', 'nomeCompleto', 'displayName'],
    email: ['email', 'e-mail', 'mail', 'userEmail', 'emailAddress'],
    password: ['password', 'senha', 'pass', 'userPassword'],
};

const ROLE_HINTS = {
    register: [
        'register',
        'registration',
        'signup',
        'signUp',
        'createUser',
        'createAccount',
        'cadastro',
        'cadastrar',
        'novoUsuario',
    ],
    login: [
        'login',
        'logIn',
        'signin',
        'signIn',
        'authenticate',
        'authentication',
        'createSession',
        'entrar',
        'autenticar',
    ],
    profile: [
        'me',
        'profile',
        'currentUser',
        'ownUser',
        'myAccount',
        'accountMe',
        'whoami',
        'self',
        'perfil',
        'usuarioAtual',
    ],
};

function normalizeName(value) {
    return String(value ?? '')
        .normalize('NFD')
        .replace(/[\u0300-\u036f]/g, '')
        .toLowerCase()
        .replace(/[^a-z0-9]/g, '');
}

function operationDescription(operationInfo) {
    const { path, method, operation } = operationInfo;
    return [
        path,
        method,
        operation.operationId,
        operation.summary,
        operation.description,
        ...(operation.tags ?? []),
    ]
        .filter(Boolean)
        .join(' ');
}

function containsHint(text, hints) {
    const normalizedText = normalizeName(text);
    const tokens = String(text ?? '')
        .split(/[^a-zA-Z0-9]+/)
        .map(normalizeName)
        .filter(Boolean);

    return hints.some((hint) => {
        const normalizedHint = normalizeName(hint);

        // Evita correspondências acidentais de termos muito curtos,
        // como "me" dentro de "username".
        if (normalizedHint.length <= 2) {
            return tokens.includes(normalizedHint);
        }

        return (
            normalizedText.includes(normalizedHint) ||
            tokens.includes(normalizedHint)
        );
    });
}

function collectSchemaProperties(schema) {
    if (!schema || typeof schema !== 'object') return {};

    const properties = { ...(schema.properties ?? {}) };

    for (const composition of ['allOf', 'oneOf', 'anyOf']) {
        for (const part of schema[composition] ?? []) {
            Object.assign(properties, collectSchemaProperties(part));
        }
    }

    return properties;
}

function collectRequiredProperties(schema) {
    if (!schema || typeof schema !== 'object') return [];

    const required = new Set(schema.required ?? []);

    for (const composition of ['allOf', 'oneOf', 'anyOf']) {
        for (const part of schema[composition] ?? []) {
            for (const property of collectRequiredProperties(part)) {
                required.add(property);
            }
        }
    }

    return [...required];
}

function matchingProperty(properties, semantic) {
    const aliases = new Set(FIELD_ALIASES[semantic].map(normalizeName));
    const matches = Object.keys(properties).filter((key) =>
        aliases.has(normalizeName(key)),
    );

    return matches.length === 1 ? matches[0] : null;
}

function getJsonRequestSchema(document, operationInfo) {
    const requestBodyRaw = operationInfo.operation.requestBody;
    if (!requestBodyRaw) return null;

    const requestBody = dereference(document, requestBodyRaw);
    const content = requestBody.content ?? {};
    const mediaType = Object.keys(content).find((type) => {
        const normalized = type.toLowerCase();
        return (
            normalized === 'application/json' || normalized.endsWith('+json')
        );
    });

    if (!mediaType) return null;

    return {
        mediaType,
        schema: dereference(document, content[mediaType].schema ?? {}),
    };
}

function enumerateOperations(document) {
    const operations = [];

    for (const [path, pathItemRaw] of Object.entries(document.paths ?? {})) {
        const pathItem = dereference(document, pathItemRaw);

        for (const [method, operation] of Object.entries(pathItem ?? {})) {
            if (
                !HTTP_METHODS.has(method.toLowerCase()) ||
                !operation ||
                typeof operation !== 'object'
            ) {
                continue;
            }

            operations.push({
                path,
                method: method.toUpperCase(),
                operation,
                pathItem,
            });
        }
    }

    return operations;
}

function getBearerSchemeNames(document) {
    return Object.entries(document.components?.securitySchemes ?? {})
        .filter(
            ([, scheme]) =>
                scheme?.type === 'http' &&
                String(scheme.scheme ?? '').toLowerCase() === 'bearer',
        )
        .map(([name]) => name);
}

function isBearerProtected(document, operationInfo, bearerSchemeNames) {
    const security = Object.hasOwn(operationInfo.operation, 'security')
        ? operationInfo.operation.security
        : document.security;

    if (!Array.isArray(security) || security.length === 0) return false;

    return security.some((requirement) =>
        bearerSchemeNames.some((name) => Object.hasOwn(requirement, name)),
    );
}

function scoreOperation(operationInfo, role) {
    const text = operationDescription(operationInfo);
    const hints = ROLE_HINTS[role];

    let score = containsHint(text, hints) ? 10 : 0;

    // O caminho tem peso maior que operationId/descrição, pois representa
    // diretamente a finalidade exposta pela API.
    if (containsHint(operationInfo.path, hints)) score += 6;
    if (containsHint(operationInfo.operation.operationId, hints)) score += 3;
    if (
        containsHint(
            `${operationInfo.operation.summary ?? ''} ${operationInfo.operation.description ?? ''}`,
            hints,
        )
    )
        score += 2;

    return score;
}

function describeCandidate(candidate) {
    const operationId = candidate.operation.operationId
        ? ` (operationId: ${candidate.operation.operationId})`
        : '';

    return `${candidate.method} ${candidate.path}${operationId}`;
}

function selectUniqueBest(candidates, role) {
    if (candidates.length === 0) {
        fail(`Nenhuma operação OpenAPI candidata foi encontrada para ${role}.`);
    }

    const ranked = candidates
        .map((candidate) => ({
            ...candidate,
            score: scoreOperation(candidate, role),
        }))
        .sort((a, b) => b.score - a.score);

    const bestScore = ranked[0].score;
    const best = ranked.filter((candidate) => candidate.score === bestScore);

    if (best.length !== 1) {
        const list = ranked
            .map(
                (candidate) =>
                    `- ${describeCandidate(candidate)} [pontuação: ${candidate.score}]`,
            )
            .join('\n');

        fail(
            `Identificação ambígua da operação de ${role}. ` +
                `Candidatas encontradas:\n${list}`,
        );
    }

    return ranked[0];
}

function discoverRegistration(document, operations) {
    const candidates = [];

    for (const operationInfo of operations) {
        if (operationInfo.method !== 'POST') continue;

        const request = getJsonRequestSchema(document, operationInfo);
        if (!request) continue;

        const properties = collectSchemaProperties(request.schema);
        const name = matchingProperty(properties, 'name');
        const email = matchingProperty(properties, 'email');
        const password = matchingProperty(properties, 'password');

        if (name && email && password) candidates.push(operationInfo);
    }

    return selectUniqueBest(candidates, 'register');
}

function discoverLogin(document, operations) {
    const candidates = [];

    for (const operationInfo of operations) {
        if (operationInfo.method !== 'POST') continue;

        const request = getJsonRequestSchema(document, operationInfo);
        if (!request) continue;

        const properties = collectSchemaProperties(request.schema);
        const email = matchingProperty(properties, 'email');
        const password = matchingProperty(properties, 'password');
        const name = matchingProperty(properties, 'name');

        if (email && password && !name) candidates.push(operationInfo);
    }

    return selectUniqueBest(candidates, 'login');
}

function discoverProfile(document, operations) {
    const bearerSchemes = getBearerSchemeNames(document);

    if (bearerSchemes.length === 0) {
        fail(
            'O OpenAPI não declara nenhum esquema HTTP Bearer em components.securitySchemes.',
        );
    }

    const candidates = operations.filter(
        (operationInfo) =>
            operationInfo.method === 'GET' &&
            isBearerProtected(document, operationInfo, bearerSchemes),
    );

    return selectUniqueBest(candidates, 'profile');
}

function getOperationUrl(document, operationInfo, baseUrl) {
    const { path, operation, pathItem } = operationInfo;
    const server =
        operation.servers?.[0] ??
        pathItem.servers?.[0] ??
        document.servers?.[0];
    let serverBase = new URL(baseUrl);

    if (server?.url) {
        if (server.url.includes('{')) {
            fail(
                `O servidor OpenAPI contém variáveis não resolvidas: ${server.url}`,
            );
        }

        const declaredServer = new URL(server.url, baseUrl);
        const configuredBase = new URL(baseUrl);

        // Usa a origem alcançável pelo runner, preservando o prefixo documentado.
        declaredServer.protocol = configuredBase.protocol;
        declaredServer.host = configuredBase.host;
        serverBase = declaredServer;
    }

    const serverPrefix = serverBase.pathname.replace(/\/+$/, '');
    const normalizedPath = path.replace(/^\//, '');
    const url = new URL(`${serverPrefix}/${normalizedPath}`, serverBase.origin);

    const parameters = [
        ...(operation.parameters ?? []),
        ...(pathItem.parameters ?? []),
    ].map((parameter) => dereference(document, parameter));

    const requiredPathParameters = parameters.filter(
        (parameter) => parameter.in === 'path' && parameter.required !== false,
    );

    if (requiredPathParameters.length > 0 || url.pathname.includes('{')) {
        fail(
            `A operação ${describeCandidate(operationInfo)} possui parâmetros de caminho obrigatórios; ` +
                'o script não os presume.',
        );
    }

    return url;
}

function buildPayload(document, operationInfo, values, requiredSemantics) {
    const request = getJsonRequestSchema(document, operationInfo);
    if (!request) {
        fail(
            `A operação ${describeCandidate(operationInfo)} não documenta corpo JSON.`,
        );
    }

    const properties = collectSchemaProperties(request.schema);
    const payload = {};

    for (const semantic of requiredSemantics) {
        const propertyName = matchingProperty(properties, semantic);

        if (!propertyName) {
            fail(
                `Não foi possível identificar unicamente o campo semântico '${semantic}' ` +
                    `no schema de ${describeCandidate(operationInfo)}.`,
            );
        }

        payload[propertyName] = values[semantic];
    }

    const required = collectRequiredProperties(request.schema);
    const missingRequired = required.filter(
        (property) => !(property in payload),
    );

    if (missingRequired.length > 0) {
        fail(
            `A operação ${describeCandidate(operationInfo)} exige campos adicionais ` +
                `não previstos no teste: ${missingRequired.join(', ')}.`,
        );
    }

    return { mediaType: request.mediaType, payload };
}

async function sendJsonRequest(
    url,
    method,
    payload,
    mediaType = 'application/json',
    headers = {},
) {
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
    const priorities = new Map([
        ['accesstoken', 1],
        ['accessjwt', 2],
        ['bearertoken', 3],
        ['token', 4],
        ['jwt', 5],
    ]);

    const matches = [];

    function visit(current) {
        if (!current || typeof current !== 'object') return;

        if (Array.isArray(current)) {
            current.forEach(visit);
            return;
        }

        for (const [key, child] of Object.entries(current)) {
            const normalizedKey = normalizeName(key);

            // Evita selecionar refreshToken ou outros tokens que não sejam de acesso.
            if (
                priorities.has(normalizedKey) &&
                typeof child === 'string' &&
                child.trim().length > 0
            ) {
                matches.push({
                    token: child.trim(),
                    priority: priorities.get(normalizedKey),
                    field: key,
                });
            } else {
                visit(child);
            }
        }
    }

    visit(value);

    if (matches.length === 0) return undefined;

    matches.sort((a, b) => a.priority - b.priority);
    const bestPriority = matches[0].priority;
    const bestMatches = matches.filter(
        (match) => match.priority === bestPriority,
    );
    const distinctTokens = [
        ...new Set(bestMatches.map((match) => match.token)),
    ];

    if (distinctTokens.length > 1) {
        fail(
            `A resposta do login contém múltiplos campos candidatos a token de acesso ` +
                `com a mesma prioridade: ${bestMatches.map((match) => match.field).join(', ')}.`,
        );
    }

    return distinctTokens[0];
}

function assertSuccessful(label, response) {
    if (!response.ok) {
        fail(
            `${label} falhou: HTTP ${response.status}. Verifique a implementação e o contrato OpenAPI.`,
        );
    }
}

async function main() {
    if (!openApiFile || !baseUrlArgument || !evidenceFile) {
        fail(
            'Uso: node prepare-dast-auth.mjs <openapi.json> <base-url> ' +
                '<authentication-evidence.json>',
        );
    }

    const document = readJsonFile(resolve(openApiFile));
    const baseUrl = new URL(baseUrlArgument);
    const operations = enumerateOperations(document);

    if (operations.length === 0) {
        fail(
            'A especificação OpenAPI não contém operações HTTP reconhecíveis.',
        );
    }

    const register = discoverRegistration(document, operations);
    const login = discoverLogin(document, operations);
    const profile = discoverProfile(document, operations);

    const uniqueId = randomUUID();
    const testUser = {
        name: 'DAST Automated User',
        email: `dast-${uniqueId}@example.test`,
        password: `Dast!Aa1${randomBytes(18).toString('hex')}`,
    };

    const registrationPayload = buildPayload(document, register, testUser, [
        'name',
        'email',
        'password',
    ]);
    const registrationUrl = getOperationUrl(document, register, baseUrl);
    const registrationResult = await sendJsonRequest(
        registrationUrl,
        register.method,
        registrationPayload.payload,
        registrationPayload.mediaType,
    );
    assertSuccessful(
        'Cadastro do usuário de teste',
        registrationResult.response,
    );

    const loginPayload = buildPayload(document, login, testUser, [
        'email',
        'password',
    ]);
    const loginUrl = getOperationUrl(document, login, baseUrl);
    const loginResult = await sendJsonRequest(
        loginUrl,
        login.method,
        loginPayload.payload,
        loginPayload.mediaType,
    );
    assertSuccessful('Autenticação do usuário de teste', loginResult.response);

    const accessToken = findAccessToken(loginResult.body);
    if (!accessToken) {
        fail(
            'A resposta do login não contém um campo de token de acesso reconhecido ' +
                '(accessToken, accessJwt, bearerToken, token ou jwt).',
        );
    }

    const profileUrl = getOperationUrl(document, profile, baseUrl);
    const profileResult = await sendJsonRequest(
        profileUrl,
        profile.method,
        undefined,
        undefined,
        { Authorization: `Bearer ${accessToken}` },
    );
    assertSuccessful(
        'Validação do acesso autenticado ao perfil',
        profileResult.response,
    );

    const envFile = process.env.GITHUB_ENV || process.env.DAST_ENV_FILE;
    if (!envFile) {
        fail(
            'GITHUB_ENV não está definido. Para execução local, defina DAST_ENV_FILE.',
        );
    }

    const headerValue = `Bearer ${accessToken}`;
    const headerSite =
        process.env.DAST_ZAP_AUTH_HEADER_SITE || 'host.docker.internal';

    if (process.env.GITHUB_ACTIONS === 'true') {
        process.stdout.write(`::add-mask::${accessToken}\n`);
        process.stdout.write(`::add-mask::${headerValue}\n`);
    }

    appendFileSync(
        envFile,
        [
            `ZAP_AUTH_HEADER_VALUE=${headerValue}`,
            'ZAP_AUTH_HEADER=Authorization',
            `ZAP_AUTH_HEADER_SITE=${headerSite}`,
            '',
        ].join('\n'),
    );

    const operationEvidence = (operationInfo, response) => ({
        operationId: operationInfo.operation.operationId ?? null,
        path: operationInfo.path,
        method: operationInfo.method,
        status: response.status,
    });

    const evidence = {
        authentication_preparation: 'success',
        operation_discovery: 'dynamic',
        user_registration: operationEvidence(
            register,
            registrationResult.response,
        ),
        user_login: operationEvidence(login, loginResult.response),
        access_token_extracted: true,
        authenticated_profile_request: operationEvidence(
            profile,
            profileResult.response,
        ),
        zap_header_prepared: true,
        zap_header_name: 'Authorization',
        zap_header_site: headerSite,
        secrets_written_to_evidence: false,
    };

    mkdirSync(dirname(resolve(evidenceFile)), { recursive: true });
    writeFileSync(
        resolve(evidenceFile),
        `${JSON.stringify(evidence, null, 2)}\n`,
        {
            mode: 0o600,
        },
    );

    process.stdout.write(
        'Sessão DAST preparada e validada por descoberta dinâmica das operações OpenAPI.\n',
    );
    process.stdout.write(`Cadastro: ${describeCandidate(register)}\n`);
    process.stdout.write(`Login: ${describeCandidate(login)}\n`);
    process.stdout.write(`Perfil: ${describeCandidate(profile)}\n`);
}

main().catch((error) => {
    process.stderr.write(`::error::${error.message}\n`);
    process.exitCode = 1;
});
