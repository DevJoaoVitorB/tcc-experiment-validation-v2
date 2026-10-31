
/*
 * Executor independente de verificações comportamentais DAST.
 *
 * Verificações:
 * 1. Acesso sem autenticação.
 * 2. Isolamento entre identidades.
 * 3. Confusão entre access token e refresh token.
 * 4. Rotação e invalidação de refresh token após logout.
 * 5. Exposição de credenciais nas respostas.
 *
 * Execução: Node.js 22.
 *
 * Variáveis:
 * DAST_BASE_URL
 * ZAP_API_URL
 * DAST_ZAP_API_KEY
 * DAST_OUTPUT_DIR
 * ZAP_PROXY_URL
 */

'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { execFileSync } = require('node:child_process');

const BASE = (process.env.DAST_BASE_URL || 'http://127.0.0.1:3000').replace(/\/+$/, '');
const ZAP = (process.env.ZAP_API_URL || 'http://127.0.0.1:8080').replace(/\/+$/, '');
const API_KEY = process.env.DAST_ZAP_API_KEY || '';
const OUTPUT = path.join(process.env.DAST_OUTPUT_DIR || 'evidence/dast', 'dast-tests.json');
const PROXY = process.env.ZAP_PROXY_URL || 'http://127.0.0.1:8080';

const tests = [];
const errors = [];
let alertErrors = 0;

const random = () => crypto.randomUUID().replace(/-/g, '');
const is2xx = status => status >= 200 && status < 300;
const isRejected = status => [400, 401, 403, 404, 405, 409, 415, 422].includes(status);

function parseJson(text) {
    try { return JSON.parse(text); } catch { return null; }
}

function tokenFrom(data, names) {
    if (!data || typeof data !== 'object') return null;
    for (const name of names) {
        if (typeof data[name] === 'string' && data[name]) return data[name];
    }
    return tokenFrom(data.data, names) || tokenFrom(data.tokens, names);
}

function zapApi(component, operation, params = {}) {
    const query = new URLSearchParams({ apikey: API_KEY, ...params });
    const url = `${ZAP}/JSON/${component}/${operation}/?${query}`;
    const output = execFileSync('curl', [
        '--silent', '--show-error', '--fail', '--max-time', '20', url
    ], { encoding: 'utf8', timeout: 25000 });
    const data = parseJson(output);
    if (!data || data.code || data.Result === 'ERROR') {
        throw new Error(`Resposta inválida da API ZAP: ${output}`);
    }
    return data;
}

function zapMessageCount() {
    const data = zapApi('core', 'view/numberOfMessages', { baseurl: BASE });
    const count = Number(data.numberOfMessages);
    if (!Number.isInteger(count) || count < 0) {
        throw new Error(`Contagem de mensagens ZAP inválida: ${JSON.stringify(data)}`);
    }
    return count;
}

function latestZapMessageId(start) {
    const data = zapApi('core', 'view/messages', {
        baseurl: BASE, start: String(start), count: '20'
    });
    const messages = data.messages || [];
    const message = messages[messages.length - 1];
    const id = message && (message.id ?? message.messageId);
    if (id === undefined || id === null || id === '') return null;
    return String(id);
}

function request(method, route, options = {}) {
    const url = BASE + route;
    const start = zapMessageCount();
    const args = [
        '--silent', '--show-error', '--max-time', '30',
        '--proxy', PROXY, '--noproxy', '',
        '--request', method,
        '--write-out', '\n__HTTP_STATUS__:%{http_code}',
        '--url', url
    ];

    if (options.token) args.push('--header', `Authorization: Bearer ${options.token}`);
    if (options.body !== undefined) {
        args.push('--header', 'Content-Type: application/json');
        args.push('--data-binary', JSON.stringify(options.body));
    }

    try {
        const output = execFileSync('curl', args, {
            encoding: 'utf8', timeout: 35000, maxBuffer: 10 * 1024 * 1024
        });
        const marker = '\n__HTTP_STATUS__:';
        const index = output.lastIndexOf(marker);
        if (index < 0) throw new Error('Código HTTP ausente.');

        const text = output.slice(0, index);
        const status = Number(output.slice(index + marker.length).trim());
        let messageId = null;

        // O alerta do ZAP precisa estar associado a uma mensagem HTTP real.
        for (let attempt = 0; attempt < 5 && !messageId; attempt++) {
            messageId = latestZapMessageId(start);
            if (!messageId) Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 200);
        }

        return { status, text, json: parseJson(text), url, method, messageId };
    } catch (error) {
        throw new Error(`${method} ${route}: ${error.message}`);
    }
}

function record(name, outcome, status, detail, evidence = '') {
    tests.push({
        id: name,
        outcome,
        httpStatus: status ?? null,
        detail,
        evidence
    });

    console.log(`[DAST] ${name} => ${outcome}; ${detail}`);
}

function result(name, status, passed, detail) {
    const outcome = passed ? 'PASS' :
        Number(status) >= 500 ? 'ERROR' : 'NOT_EVALUATED';

    record(name, outcome, status, detail, status ? `HTTP ${status}` : '');
}

function submitAlert(response, name, detail, risk, evidence) {
    if (!response.messageId) {
        throw new Error('A requisição não possui messageId registrado no ZAP.');
    }

    const data = zapApi('alert', 'action/addAlert', {
        messageId: response.messageId,
        name,
        riskId: String(risk ?? 2),
        confidenceId: '2',
        description: detail,
        param: name,
        attack: '',
        evidence: evidence || `HTTP ${response.status}`,
        otherInfo: 'Achado identificado por teste comportamental automatizado.',
        solution: 'Valide autenticação e autorização no servidor; diferencie access tokens de refresh tokens; invalide refresh tokens após logout e rotação.',
        references: 'https://www.zaproxy.org/docs/api/',
        cweId: '862',
        wascId: '0'
    });

    if (!data.id && !data.alertId && !data.Result) {
        throw new Error(`ZAP não confirmou a criação do alerta: ${JSON.stringify(data)}`);
    }
}

function finding(response, name, detail, risk = 2, evidence = '') {
    record(name, 'FAIL', response.status, detail, evidence || `HTTP ${response.status}`);

    try {
        submitAlert(response, name, detail, risk, evidence);
    } catch (error) {
        alertErrors++;
        errors.push(`Falha ao enviar alerta "${name}": ${error.message}`);
        console.error(`[DAST] ERROR: ${error.message}`);
    }
}

function checkRejected(response, name, detail, risk = 2) {
    if (isRejected(response.status)) {
        result(name, response.status, true, detail);
    } else if (is2xx(response.status)) {
        finding(response, name, `${detail} A API aceitou a requisição que deveria ser recusada.`, risk);
    } else {
        result(name, response.status, false, `${detail} Resposta inconclusiva.`);
    }
}

function registerAccount(label) {
    const account = {
        email: `dast-extra-${label}-${random()}@example.invalid`,
        password: `Dast-${random()}!`,
        created: false,
        access: null,
        refresh: null
    };

    const registration = request('POST', '/auth/register', {
        body: {
            name: `DAST Extra User ${label}`,
            email: account.email,
            password: account.password
        }
    });

    account.created = [200, 201, 202].includes(registration.status);

    if (!account.created) {
        result(`Preparação: cadastro ${label}`, registration.status, false,
            'Não foi possível criar a conta temporária.');
        return account;
    }

    record(`Preparação: cadastro ${label}`, 'PASS', registration.status,
        'Conta temporária criada.');

    const login = request('POST', '/auth/login', {
        body: { email: account.email, password: account.password }
    });

    if (is2xx(login.status)) {
        account.access = tokenFrom(login.json, ['accessToken', 'access_token', 'token']);
        account.refresh = tokenFrom(login.json, ['refreshToken', 'refresh_token']);
    }

    record(`Preparação: login ${label}`,
        account.access ? 'PASS' : login.status >= 500 ? 'ERROR' : 'NOT_EVALUATED',
        login.status,
        account.access ? 'Access token obtido.' : 'Access token não obtido.');

    return account;
}

function checkNoCredentialLeak(response, name, password, expectedStatus) {
    const text = response.text || '';
    let leak = password && text.includes(password) ? 'senha sentinela refletida' : null;

    function inspect(object, prefix = '') {
        if (!object || typeof object !== 'object') return null;

        for (const [key, value] of Object.entries(object)) {
            if (/^(password|passwd|passwordhash|password_hash|hashedpassword|password_digest|credentialhash|credential_hash)$/i.test(key) &&
                value !== null && value !== '' && value !== false) {
                return prefix + key;
            }

            if (value && typeof value === 'object') {
                const nested = inspect(value, `${prefix}${key}.`);
                if (nested) return nested;
            }
        }

        return null;
    }

    leak = leak || inspect(response.json);

    if (leak) {
        finding(response, name,
            `A resposta contém senha ou campo de senha/hash não vazio (${leak}).`,
            3, leak);
    } else if (
        response.status >= 500 ||
        (expectedStatus === 'rejected' && !isRejected(response.status)) ||
        (expectedStatus !== 'rejected' && !is2xx(response.status))
    ) {
        result(name, response.status, false,
            'Não foi possível concluir a verificação devido à resposta recebida.');
    } else {
        result(name, response.status, true,
            'Nenhuma senha sentinela ou campo explícito de senha/hash foi detectado; isso não prova segurança do armazenamento.');
    }
}

function runSuite() {
    console.log(`[DAST] Início da suíte complementar em ${BASE}`);

    // 1. Acesso sem autenticação.
    checkRejected(
        request('GET', '/users/me'),
        'GET /users/me sem autenticação',
        'O perfil deve exigir autenticação.',
        3
    );

    const a = registerAccount('a');
    const b = registerAccount('b');

    // 2. Isolamento entre identidades.
    if (a.access && b.access) {
        const pa = request('GET', '/users/me', { token: a.access });
        const pb = request('GET', '/users/me', { token: b.access });

        const validA = pa.text.includes(a.email) && !pa.text.includes(b.email);
        const validB = pb.text.includes(b.email) && !pb.text.includes(a.email);

        if (validA && validB) {
            result('Isolamento dos perfis A/B', 200, true,
                'Cada conta recebeu sua própria identidade.');
        } else if (is2xx(pa.status) && is2xx(pb.status) &&
            (pa.text.includes(b.email) || pb.text.includes(a.email))) {
            finding(pb, 'Isolamento dos perfis A/B',
                'Uma resposta de perfil parece conter a identidade da outra conta.',
                3, 'Possível exposição cruzada de e-mail entre contas');
        } else {
            result('Isolamento dos perfis A/B', pa.status, false,
                'Não foi possível confirmar o formato de identidade das respostas.');
        }
    } else {
        result('Isolamento dos perfis A/B', null, false,
            'Duas contas/tokens não disponíveis.');
    }

    // 3. Confusão entre tipos de token.
    if (a.refresh) {
        checkRejected(
            request('GET', '/users/me', { token: a.refresh }),
            'Refresh token usado como access token',
            'Refresh token não deve autorizar recursos protegidos.',
            3
        );
    } else {
        result('Refresh token usado como access token', null, false,
            'Refresh token ausente.');
    }

    if (a.access) {
        checkRejected(
            request('POST', '/auth/refresh', { body: { refreshToken: a.access } }),
            'Access token usado como refresh token',
            'Access token não deve ser aceito como credencial de renovação.',
            3
        );
    } else {
        result('Access token usado como refresh token', null, false,
            'Access token ausente.');
    }

    // 4. Rotação e invalidação após logout.
    if (a.created) {
        const session = request('POST', '/auth/login', {
            body: { email: a.email, password: a.password }
        });

        const refresh = tokenFrom(session.json, ['refreshToken', 'refresh_token']);

        if (refresh) {
            const rotated = request('POST', '/auth/refresh', {
                body: { refreshToken: refresh }
            });

            if (is2xx(rotated.status)) {
                checkRejected(
                    request('POST', '/auth/refresh', {
                        body: { refreshToken: refresh }
                    }),
                    'Reutilização de refresh token após rotação',
                    'O token anterior deve ser invalidado quando há rotação.',
                    2
                );
            } else {
                result('Reutilização de refresh token após rotação',
                    rotated.status, false, 'Renovação inicial não funcionou.');
            }

            const logoutSession = request('POST', '/auth/login', {
                body: { email: a.email, password: a.password }
            });

            const logoutAccess = tokenFrom(logoutSession.json,
                ['accessToken', 'access_token', 'token']);
            const logoutRefresh = tokenFrom(logoutSession.json,
                ['refreshToken', 'refresh_token']);

            if (logoutAccess && logoutRefresh) {
                const logout = request('POST', '/auth/logout', {
                    token: logoutAccess,
                    body: { refreshToken: logoutRefresh }
                });

                if (is2xx(logout.status)) {
                    checkRejected(
                        request('POST', '/auth/refresh', {
                            body: { refreshToken: logoutRefresh }
                        }),
                        'Refresh token após logout',
                        'Refresh token revogado não deve renovar a sessão.',
                        2
                    );
                } else {
                    result('Refresh token após logout', logout.status, false,
                        'Logout não confirmou sucesso.');
                }
            } else {
                result('Refresh token após logout', null, false,
                    'Tokens da sessão de logout ausentes.');
            }
        } else {
            result('Rotação/logout de refresh token', null, false,
                'Refresh token ausente.');
        }
    }

    // 5. Exposição de credenciais.
    const sentinel = `Sentinel-${random()}!`;

    const registration = request('POST', '/auth/register', {
        body: {
            name: 'DAST Credential Check',
            email: `dast-cred-${random()}@example.invalid`,
            password: sentinel
        }
    });

    const invalidLogin = request('POST', '/auth/login', {
        body: {
            email: `missing-${random()}@example.invalid`,
            password: `Sentinel-${random()}!`
        }
    });

    checkNoCredentialLeak(registration,
        'Cadastro não expõe senha/hash', sentinel);

    checkNoCredentialLeak(invalidLogin,
        'Login inválido não expõe senha/hash', null, 'rejected');

    if (a.access) {
        checkNoCredentialLeak(
            request('GET', '/users/me', { token: a.access }),
            'Perfil não expõe senha/hash',
            a.password
        );
    } else {
        result('Perfil não expõe senha/hash', null, false,
            'Access token indisponível.');
    }

    console.log('[DAST] Fim da suíte complementar.');
}

function writeSummary() {
    const counts = { PASS: 0, FAIL: 0, NOT_EVALUATED: 0, ERROR: 0 };

    for (const test of tests) counts[test.outcome]++;

    const summary = {
        schemaVersion: 1,
        completed: errors.length === 0,
        total: tests.length,
        counts,
        alertSubmissionErrors: alertErrors,
        infrastructureErrors: errors,
        tests
    };

    fs.mkdirSync(path.dirname(OUTPUT), { recursive: true });
    fs.writeFileSync(OUTPUT, JSON.stringify(summary, null, 2), 'utf8');

    console.log(`[DAST] Resumo salvo em ${OUTPUT}: ${JSON.stringify(counts)}`);
}

function main() {
    try {
        if (!API_KEY) throw new Error('DAST_ZAP_API_KEY não configurada.');
        runSuite();
    } catch (error) {
        errors.push(error.message);
        console.error(`[DAST] ERROR: ${error.message}`);
    } finally {
        try {
            writeSummary();
        } catch (error) {
            errors.push(`Falha ao salvar resumo: ${error.message}`);
            console.error(`[DAST] ERROR: ${error.message}`);
        }
    }

    if (errors.length) process.exitCode = 1;
}

main();
