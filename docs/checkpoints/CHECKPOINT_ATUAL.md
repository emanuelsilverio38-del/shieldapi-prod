# ShieldAPI - Checkpoint Atual

Data do checkpoint: 2026-05-24

## Estado Geral

Projeto: ShieldAPI / ShieldAPI-Prod

Objetivo: API profissional de seguranca, inteligencia e decisao para tokens Solana, usada por agentes IA, bots de trading, screeners, dashboards Web3 e ferramentas de developers.

Posicionamento:

Security and intelligence API for Solana AI agents, trading bots and token scanners.

Frase central:

Antes do teu bot, agente ou scanner interagir com um token Solana, chama a ShieldAPI.

A ShieldAPI deve ser vendida como camada de protecao, decisao e inteligencia antes de bots, agentes ou apps interagirem com tokens Solana. Nao deve ser vendida como bot de lucro nem como promessa de rendimento.

## Estado Tecnico Atual

Pasta local: `C:\ShieldAPI-Prod`

API Railway:

`https://zucchini-caring-production.up.railway.app`

Branch: `main`

Estado atual da API: ShieldAPI v4.7 real restaurada do commit `5354968`.

Stack atual:

- Node.js
- Railway
- PostgreSQL Railway
- Stripe em modo teste
- API keys por cliente
- Cache em memoria + PostgreSQL
- Dexscreener como fonte principal atual
- Dispatcher modular iniciado
- `server.js` ainda e o ficheiro principal

## Funcionalidade Existente Antes da Modularizacao

Rotas funcionais:

- `GET /health`
- `GET /docs`
- `GET /analyze`
- `GET /analyze-fast`
- `POST /submit`
- `GET /cache/stats`
- `GET /usage`
- `POST /billing/create-checkout-session`
- `GET /billing/success`
- `GET /billing/cancel`
- `POST /billing/portal`
- `POST /webhooks/stripe`
- `POST /admin/clients/create`
- `GET /admin/clients`
- `POST /admin/clients/disable`
- `GET /admin/clients/usage`

Funcionalidades ja implementadas:

- Analise inicial baseada em Dexscreener
- `riskScore`, `riskLevel` e `opportunityScore` iniciais
- Cache em memoria
- Cache persistente em PostgreSQL
- Usage stats
- Rate limit
- API keys por cliente
- Hash SHA-256 das API keys
- Planos Free, Starter, Pro, Advanced e Enterprise
- Quotas por plano
- Admin cria, lista e desativa clientes
- Stripe Checkout
- Stripe Webhook
- Criacao automatica de cliente apos pagamento
- Geracao automatica de API key apos pagamento
- Entrega de API key via `/billing/success`
- Cliente consegue usar `/usage` com key criada
- API key desativada devolve 403

## Modularizacao Ja Feita

Dispatcher modular:

- `src/routes/index.js`

O `server.js` importa:

```js
import { handleRoute, getKnownRoutes } from './src/routes/index.js';
```

Modulos ja criados:

- `src/auth/rateLimit.js`
- `src/auth/quota.js`
- `src/db/clientsRepository.js`
- `src/db/usageRepository.js`
- `src/billing/stripeClient.js`
- `src/billing/checkout.js`
- `src/billing/portal.js`
- `src/billing/webhook.js`
- `src/routes/health.js`
- `src/routes/billing.js`
- `src/routes/admin.js`
- `src/routes/analyze.js`
- `src/routes/index.js`
- `src/routes/docs.js`
- `src/routes/root.js`

Rotas ja migradas para dispatcher modular:

- `GET /`
- `GET /health`
- `GET /docs`
- `GET /cache/stats`
- `GET /billing/cancel`

Estas rotas foram testadas localmente e em producao.

## Alteracoes Recentes Concluidas

### Migracao de `/docs`

Criado:

- `src/routes/docs.js`

Adicionado ao dispatcher:

- `GET /docs`

Alterado `server.js` para deixar `/docs` passar pelo `handleRoute`.

Teste local:

- `/docs` devolveu JSON completo com `name`, `version`, `description`, `endpoints`, `plans`, `roadmap` e `securityNotes`.

Teste producao Railway:

- `/docs` devolveu 200 OK.

Commit:

- `Migrate docs route to modular dispatcher`

Backups criados:

- `server_backup_before_docs_migration.js`
- `server_backup_after_docs_migration.js`

Commit:

- `Add backup after docs route migration`

### Migracao de `/`

Criado:

- `src/routes/root.js`

Adicionado ao dispatcher:

- `GET /`

Alterado `server.js` para deixar `/` passar pelo `handleRoute`.

Fallback final do `server.js` alterado:

- Antes: rotas inexistentes devolviam 200 generico.
- Agora: rotas inexistentes devolvem 404 `NOT_FOUND`.

Testes:

- `/` devolveu 200.
- `/docs` devolveu 200.
- `/health` devolveu 200.
- rota inexistente devolveu 404.

Commit:

- `Migrate root route to modular dispatcher`

### `routeContext` Criado

Objetivo:

Evitar passar apenas `{ pool: dbPool }` e preparar o dispatcher para receber dependencias reais.

`routeContext` atual:

```js
const routeContext = {
  pool: dbPool,
  dbPool,
  dbReady,
  stripe,
  version: VERSION,
  startedAt,
  responseTimeMs
};
```

Rotas que usam `routeContext` agora:

- `/`
- `/health`
- `/docs`
- `/cache/stats`
- `/billing/cancel`

Teste local apos `routeContext`:

- `/` 200
- `/docs` 200
- `/health` 200
- `/cache/stats` 200
- `/billing/cancel` 200
- rota inexistente 404

Teste producao apos `routeContext`:

- `/` 200
- `/docs` 200
- `/health` 200
- `/cache/stats` 200
- `/billing/cancel` 200
- `/not-existing-route-context-test` 404

Commit:

- `Add shared route context for modular dispatcher`

## Testes de Producao Confirmados

Produção Railway confirmou:

- `GET /` -> 200 OK
- `GET /docs` -> 200 OK
- `GET /health` -> 200 OK
- `GET /cache/stats` -> 200 OK
- `GET /billing/cancel` -> 200 OK
- rota inexistente -> 404 `NOT_FOUND`

Comando usado para 404:

```powershell
try {
  Invoke-WebRequest "https://zucchini-caring-production.up.railway.app/not-existing-route-context-test"
} catch {
  $_.Exception.Response.StatusCode.value__
}
```

Resultado:

```text
404
```

## Estado do Git no Checkpoint

Historico indicado antes deste checkpoint:

- `ScannerAgent.js` modificado
- `server_backup_v4_2.js` nao rastreado

Regra importante:

Nao usar `git add .`.

Usar sempre `git add` especifico para evitar incluir alteracoes antigas por acidente.

Exemplo correto:

```powershell
git add server.js src/routes/index.js src/routes/root.js
```

Exemplo a evitar:

```powershell
git add .
```

Nota deste checkpoint local:

Ao verificar localmente em 2026-05-24, `git status --short` nao devolveu pendencias visiveis.

## Rotas Que Nao Devem Ser Migradas As Cegas

Nao migrar ainda sem adaptar contexto, auth, DB, Stripe e comportamento legado:

- `/usage`
- `/admin/*`
- `/billing/success`
- `/billing/create-checkout-session`
- `/billing/portal`
- `/webhooks/stripe`
- `/analyze`
- `/analyze-fast`
- `/submit`

Motivo:

Estas rotas dependem de uma ou mais partes criticas:

- API keys
- Clientes
- Quota
- Rate limit
- Usage
- PostgreSQL
- Stripe
- Webhook signature
- `api_key_delivery`
- Cache
- Dexscreener
- Logica de analise
- Criacao/atualizacao de cliente
- Entrega de API key apos pagamento

Exemplo importante:

`/billing/success` no `server.js`:

- Le `session_id`
- Chama `stripe.checkout.sessions.retrieve(...)`
- Chama `createOrUpdateClientFromCheckoutSession(session)`
- Le `api_key_delivery` na DB
- Marca API key como consumida
- Entrega a API key ao cliente

Conclusao:

Nao migrar `/billing/success` agora sem adaptar contexto completo de billing, DB e Stripe.

## Proxima Fase Recomendada

Antes de migrar rotas criticas, preparar melhor a base modular:

1. Criar backup/checkpoint atual.
2. Criar validators.
3. Criar policies.
4. Criar observability/logger basico.
5. Corrigir inconsistencias do `/health`.
6. So depois migrar `/usage`.
7. Depois migrar `/admin/*` com `adminAuth` correto.
8. Depois migrar billing critico com Stripe context completo.
9. Depois migrar `/analyze`, `/analyze-fast` e `/submit`.
10. Depois construir ShieldAPI v4.8 Security Module Pro.

Mini-fase recomendada:

Criar base de `validators`, `policies` e `observability` antes de migrar `/usage`.

Alternativa:

Migrar `/usage`, mas so depois de comparar:

- `handleUsage` no `server.js`
- `handleUsage` em `src/routes/analyze.js`
- Autenticacao/API key usada
- Quota e DB necessarias

Regra:

Nao migrar `/usage` sem primeiro confirmar auth/context.

## Modulos Arquiteturais Acrescentados Ao Plano

### `src/validators`

Objetivo:

Validar inputs antes de executar logica.

Ficheiros planeados:

- `solanaAddressValidator.js`
- `requestValidator.js`
- `billingValidator.js`
- `analyzeValidator.js`
- `quoteValidator.js`
- `adminValidator.js`

### `src/policies`

Objetivo:

Centralizar regras de negocio e thresholds.

Ficheiros planeados:

- `planPolicies.js`
- `riskPolicies.js`
- `billingPolicies.js`
- `cachePolicies.js`
- `scoringPolicies.js`
- `executionPolicies.js`

### `src/observability`

Objetivo:

Logs, metricas, erros, latencia, monitorizacao externa e audit log.

Ficheiros planeados:

- `logger.js`
- `metrics.js`
- `errorReporter.js`
- `latencyTracker.js`
- `externalApiMonitor.js`
- `auditLog.js`

## Prioridade Estrategica

Maior prioridade tecnica/comercial:

ShieldAPI v4.8 Security Module Pro.

O que falta:

- RugCheck
- Mint authority
- Freeze authority
- Holders concentration
- Top holders
- Creator risk
- LP/liquidity risk real
- Metadata checks
- Blacklist
- Wash trading provavel
- Historico de risco
- `reasons`, `warnings` e `blockingReasons` melhores

Objetivo do `/analyze` futuro:

Responder com:

- `APPROVED`
- `WARNING`
- `BLOCKED`

Com explicacao clara.

## Execution Module Futuro

O Execution Module nao e prioridade agora.

Modelo seguro futuro:

- `/quote`
- `/prepare-swap`
- Cliente assina e executa

Regras:

- ShieldAPI nunca guarda private keys.
- ShieldAPI nunca assina transacoes dos clientes.
- Cliente mantem controlo da wallet.
- ShieldAPI so prepara quote/transacao sem assinatura.
- Cliente assina com wallet/infra propria.

So criar este modulo depois do Security Module Pro estar forte.

## Estado Final Deste Checkpoint

Concluido:

- v4.7 real restaurada
- Dispatcher modular iniciado
- `/docs` migrado
- `/` migrado
- `/health` ja modular
- `/cache/stats` ja modular
- `/billing/cancel` ja modular
- 404 profissional implementado
- `routeContext` criado
- Producao Railway testada
- GitHub sincronizado para alteracoes principais

Pendente:

- Verificar se ha pendencias antigas locais antes de cada commit
- Rotas criticas ainda no `server.js`
- `validators`, `policies` e `observability` ainda por criar
- Security Module Pro ainda por construir
- Dashboard ainda por construir
- Docs publicas ainda por construir
- Tests ainda por construir
