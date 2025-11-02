# 📘 LogLineOS Blueprint4 — Universal, Ledger-Only Backend

**Status:** Production-Ready  
**Scope:** Complete specification for LogLineOS on AWS  
**Design:** Semantic columns (~70), append-only, signed spans, multitenancy, ledger-only runtime  

> **Para execução 100% AWS e automação total, ver [Anexo A](#anexo-a-execução-100-aws-automação-total).**

---

## Executive Summary / Resumo Executivo

**EN** — LogLineOS is a ledger-only backend where every behavior (executors, observers, policies, providers, prompt compiler/bandit) is stored as versioned spans (`entity_type='function'`, seq↑). The only code outside the ledger is a Stage-0 loader that boots a whitelisted function by ID, verifies signatures/hashes, and executes it. All outputs are signed, append-only events with traceability.

**PT** — O LogLineOS é um backend 100% ledger onde todas as regras (executores, observadores, políticas, providers, compilador/bandit de prompt) vivem como spans versionados (`entity_type='function'`, seq crescente). O único código fora do ledger é o Stage-0 loader, que inicializa uma função permitida pelo Manifest, verifica assinaturas/hashes e executa. Toda saída é um evento assinado, append-only e rastreável.

---

## Table of Contents

1. [Schema & RLS (Postgres)](#1-schema--rls-postgres--esquema--rls-postgres)
2. [Stage-0 Loader](#2-stage0-loader-denonode--carregador-stage0-denonode)
3. [Kernel Suite](#3-kernel-suite-ledger-only-architecture)
4. [Prompt System Kernels](#4-prompt-system-kernels--kernels-do-sistema-de-prompts)
5. [Policies](#5-policies-ledger-only--políticas-100-ledger)
6. [Manifest & Governance](#6-manifest--governance--manifesto--governança)
7. [API Layer (Edge)](#7-api-layer-edge--camada-de-api-edge)
8. [Frontend-Agnostic Adapters](#8-frontendagnostic-adapters--adaptadores-agnósticos-de-frontend)
9. [Prompt System Seeds](#9-prompt-system-seeds--sementes-do-sistema-de-prompts)
10. [Operations Playbook](#10-operations-playbook--runbook-operacional)
11. [Security Notes](#11-security-notes--notas-de-segurança)
12. [LLM-Friendly Index](#12-llmfriendly-index--índice-amigável-a-llms)
13. [Quickstart Commands](#13-quickstart-commands--comandos-rápidos)
14. [Memory System](#14-memory-system--sistema-de-memória)
15. [**Anexo A: Execução 100% AWS (Automação Total)**](#anexo-a-execução-100-aws-automação-total)

---

## 1) Schema & RLS (Postgres) / Esquema & RLS (Postgres)

> **Ver Anexo A: P0** para implementação completa no AWS RDS/Aurora

Note: We keep the "~70 semantic columns" philosophy, but show a pragmatic core table + jsonb for rare fields.  
Obs: Mantemos a filosofia das "~70 colunas semânticas", mas mostramos um núcleo prático + jsonb para raridades.

```sql
-- Enable UUIDs and crypto helpers (if needed)
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Namespaces
CREATE SCHEMA IF NOT EXISTS app;
CREATE SCHEMA IF NOT EXISTS ledger;

-- Session accessors for RLS
CREATE OR REPLACE FUNCTION app.current_user_id() RETURNS text
LANGUAGE sql STABLE AS $$ SELECT current_setting('app.user_id', true) $$;

CREATE OR REPLACE FUNCTION app.current_tenant_id() RETURNS text
LANGUAGE sql STABLE AS $$ SELECT current_setting('app.tenant_id', true) $$;

-- Universal registry (append-only)
CREATE TABLE IF NOT EXISTS ledger.universal_registry (
  id            uuid        NOT NULL,
  seq           integer     NOT NULL,
  entity_type   text        NOT NULL,   -- e.g., function, execution, request, policy, provider, metric, prompt_*
  who           text        NOT NULL,
  did           text,
  "this"        text        NOT NULL,
  at            timestamptz NOT NULL DEFAULT now(),

  -- Relationships
  parent_id     uuid,
  related_to    uuid[],

  -- Access control
  owner_id      text,
  tenant_id     text,
  visibility    text        NOT NULL DEFAULT 'private', -- private|tenant|public

  -- Lifecycle
  status        text,       -- draft|scheduled|queued|running|complete|error|active|open|pass|fail|slow|...
  is_deleted    boolean     NOT NULL DEFAULT false,

  -- Code & Execution
  name          text,
  description   text,
  code          text,
  language      text,
  runtime       text,
  input         jsonb,
  output        jsonb,
  error         jsonb,

  -- Quantitative/metrics
  duration_ms   integer,
  trace_id      text,

  -- Crypto proofs
  prev_hash     text,
  curr_hash     text,
  signature     text,
  public_key    text,

  -- Extensibility
  metadata      jsonb,

  PRIMARY KEY (id, seq),
  CONSTRAINT ck_visibility CHECK (visibility IN ('private','tenant','public')),
  CONSTRAINT ck_append_only CHECK (seq >= 0)
);

-- "Visible timeline" view: legacy alias "when" → "at" for kernels that expect it
CREATE OR REPLACE VIEW ledger.visible_timeline AS
SELECT
  ur.*,
  ur.at AS "when"
FROM ledger.universal_registry ur
WHERE ur.is_deleted = false;

-- Append-only enforcement: disallow UPDATE/DELETE
CREATE OR REPLACE FUNCTION ledger.no_updates() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'Append-only table: updates/deletes are not allowed.';
END; $$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_trigger WHERE tgname = 'ur_no_update'
  ) THEN
    CREATE TRIGGER ur_no_update BEFORE UPDATE OR DELETE ON ledger.universal_registry
    FOR EACH ROW EXECUTE FUNCTION ledger.no_updates();
  END IF;
END $$;

-- Notify on insert for SSE
CREATE OR REPLACE FUNCTION ledger.notify_timeline() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  PERFORM pg_notify('timeline_updates', row_to_json(NEW)::text);
  RETURN NEW;
END; $$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_trigger WHERE tgname = 'ur_notify_insert'
  ) THEN
    CREATE TRIGGER ur_notify_insert AFTER INSERT ON ledger.universal_registry
    FOR EACH ROW EXECUTE FUNCTION ledger.notify_timeline();
  END IF;
END $$;

-- Useful indexes
CREATE INDEX IF NOT EXISTS ur_idx_at ON ledger.universal_registry (at DESC);
CREATE INDEX IF NOT EXISTS ur_idx_entity ON ledger.universal_registry (entity_type, at DESC);
CREATE INDEX IF NOT EXISTS ur_idx_owner_tenant ON ledger.universal_registry (owner_id, tenant_id);
CREATE INDEX IF NOT EXISTS ur_idx_trace ON ledger.universal_registry (trace_id);
CREATE INDEX IF NOT EXISTS ur_idx_parent ON ledger.universal_registry (parent_id);
CREATE INDEX IF NOT EXISTS ur_idx_related ON ledger.universal_registry USING GIN (related_to);
CREATE INDEX IF NOT EXISTS ur_idx_metadata ON ledger.universal_registry USING GIN (metadata);

-- ✅ FIX: Idempotency for observer-generated requests (prevents duplicate scheduling)
CREATE UNIQUE INDEX IF NOT EXISTS ur_idx_request_idempotent
  ON ledger.universal_registry (parent_id, entity_type, status)
  WHERE entity_type = 'request' AND status = 'scheduled' AND is_deleted = false;

-- RLS
ALTER TABLE ledger.universal_registry ENABLE ROW LEVEL SECURITY;

-- SELECT: owner OR same tenant with visibility tenant/public OR visibility public
CREATE POLICY ur_select_policy ON ledger.universal_registry
  FOR SELECT USING (
    (owner_id IS NOT DISTINCT FROM app.current_user_id())
    OR (visibility = 'public')
    OR (tenant_id IS NOT DISTINCT FROM app.current_tenant_id() AND visibility IN ('tenant','public'))
  );

-- INSERT: requester must set app.user_id; row owner_id = app.user_id; tenant matches session if provided
CREATE POLICY ur_insert_policy ON ledger.universal_registry
  FOR INSERT WITH CHECK (
    owner_id IS NOT DISTINCT FROM app.current_user_id()
    AND (tenant_id IS NULL OR tenant_id IS NOT DISTINCT FROM app.current_tenant_id())
  );
```

**Why "at" + "when"?** We store as `at` (column), expose `when` via view for kernels that used "when".  
**Por que "at" + "when"?** Gravamos em `at` e expomos "when" na view para manter compatibilidade.

---

## 2) Stage-0 Loader (Deno/Node) / Carregador Stage-0 (Deno/Node)

> **Ver Anexo A: P1** para implementação AWS Lambda

Immutable bootstrap binary. It fetches a whitelisted function from the Manifest, verifies hash/signature, executes it with a minimal context, and appends a boot_event.  
Binário imutável. Busca função permitida no Manifest, verifica hash/assinatura, executa com contexto mínimo e registra boot_event.

```typescript
// stage0_loader.ts — Deno (recommended) or Node 18+ (ESM)
import pg from "https://esm.sh/pg@8.11.3";
import { blake3 } from "https://esm.sh/@noble/hashes@1.3.3/blake3";
import * as ed from "https://esm.sh/@noble/ed25519@2.1.1";

const { Client } = pg;
const hex = (u8: Uint8Array) => Array.from(u8).map(b=>b.toString(16).padStart(2,"0")).join("");
const toU8 = (h: string) => Uint8Array.from(h.match(/.{1,2}/g)!.map(x=>parseInt(x,16)));

const DATABASE_URL   = Deno.env.get("DATABASE_URL")!;
const BOOT_FUNCTION_ID = Deno.env.get("BOOT_FUNCTION_ID")!; // must be in manifest.allowed_boot_ids
const APP_USER_ID    = Deno.env.get("APP_USER_ID") || "edge:stage0";
const APP_TENANT_ID  = Deno.env.get("APP_TENANT_ID") || null;
const SIGNING_KEY_HEX= Deno.env.get("SIGNING_KEY_HEX") || undefined;

async function withPg<T>(fn:(c:any)=>Promise<T>):Promise<T>{
  const c = new Client({ connectionString: DATABASE_URL }); await c.connect();
  try {
    await c.query(`SET app.user_id = $1`, [APP_USER_ID]);
    if (APP_TENANT_ID) await c.query(`SET app.tenant_id = $1`, [APP_TENANT_ID]);
    return await fn(c);
  } finally { await c.end(); }
}

// A safe, standard SQL tagged template literal factory.
// This prevents SQL injection by design. Kernels will use this.
function createSafeSql(client: pg.Client) {
  return async function sql(strings: TemplateStringsArray, ...values: any[]) {
    const queryText = strings.reduce((prev, curr, i) => {
      return prev + (i > 0 ? `$${i}` : "") + curr;
    }, "");
    return client.query(queryText, values);
  };
}

async function latestManifest(){
  const { rows } = await withPg(c => c.query(
    `SELECT * FROM ledger.visible_timeline WHERE entity_type='manifest' ORDER BY "when" DESC LIMIT 1`));
  return rows[0] || { metadata:{} };
}

async function verifySpan(span:any){
  const clone = structuredClone(span);
  delete clone.signature; // sign curr_hash over the canonical payload
  const msg = new TextEncoder().encode(JSON.stringify(clone, Object.keys(clone).sort()));
  const h = hex(blake3(msg));
  if (span.curr_hash && span.curr_hash !== h) throw new Error("hash mismatch");
  if (span.signature && span.public_key){
    const ok = await ed.verify(toU8(span.signature), toU8(h), toU8(span.public_key));
    if (!ok) throw new Error("invalid signature");
  }
}

async function fetchLatestFunction(id:string){
  const { rows } = await withPg(c=>c.query(`
    SELECT * FROM ledger.visible_timeline
    WHERE id=$1 AND entity_type='function'
    ORDER BY "when" DESC, seq DESC LIMIT 1`, [id]));
  if (!rows[0]) throw new Error("function span not found");
  return rows[0];
}

async function insertSpan(span:any){
  await withPg(async c=>{
    const cols = Object.keys(span), vals = Object.values(span);
    const placeholders = cols.map((_,i)=>`$${i+1}`).join(",");
    await c.query(`INSERT INTO ledger.universal_registry (${cols.map(x=>`"${x}"`).join(",")})
                   VALUES (${placeholders})`, vals);
  });
}

function now(){ return new Date().toISOString(); }

async function run(){
  const manifest = await latestManifest();
  const allow = (manifest.metadata?.allowed_boot_ids||[]) as string[];
  if (!allow.includes(BOOT_FUNCTION_ID)) throw new Error("BOOT_FUNCTION_ID not allowed by manifest");

  const fnSpan = await fetchLatestFunction(BOOT_FUNCTION_ID);
  await verifySpan(fnSpan);

  // Boot event (audit)
  await insertSpan({
    id: crypto.randomUUID(), seq:0, entity_type:'boot_event',
    who:'edge:stage0', did:'booted', this:'stage0',
    at: now(), status:'complete',
    input:{ boot_id: BOOT_FUNCTION_ID, env: { user: APP_USER_ID, tenant: APP_TENANT_ID } },
    owner_id: fnSpan.owner_id, tenant_id: fnSpan.tenant_id, visibility: fnSpan.visibility ?? 'private',
    related_to:[BOOT_FUNCTION_ID]
  });

  // Execute function code
  const factory = new Function("ctx", `"use strict";\n${String(fnSpan.code||"")}\n;return (typeof default!=='undefined'?default:globalThis.main);`);
  
  // ✅ HARDENED: Provide a secure DB access pattern to kernels.
  const ctx = {
    env: { APP_USER_ID, APP_TENANT_ID, SIGNING_KEY_HEX },
    withDb: async <T>(fn: (db: { sql: ReturnType<typeof createSafeSql> }) => Promise<T>): Promise<T> => {
      return withPg(async (client) => {
        const sql = createSafeSql(client);
        return fn({ sql });
      });
    },
    sql: (strings:TemplateStringsArray, ...vals:any[]) =>
      withPg(async (client) => {
        const sql = createSafeSql(client);
        return sql(strings, ...vals);
      }),
    insertSpan,
    now,
    crypto: { blake3, ed25519: ed, hex, toU8, randomUUID: crypto.randomUUID }
  };
  const main:any = factory(ctx);
  if (typeof main !== "function") throw new Error("kernel has no default/main export");
  await main(ctx);
}

if (import.meta.main) run().catch(e=>{ console.error(e); Deno.exit(1); });
```

**Recommendation:** Run Stage-0 on Deno / Cloud Run / Fly.io (Workers may restrict creating Web Workers).  
**Recomendação:** Execute o Stage-0 em Deno / Cloud Run / Fly.io (alguns providers edge proíbem Worker).

---

## 3) Kernel Suite (Ledger-Only Architecture)

> **Ver Anexo A: P1-P2** para deployment completo no AWS Lambda + EventBridge

**Purpose:** This section defines the five core execution kernels that constitute the LogLineOS runtime. All kernels are stored as versioned spans within the ledger itself, loaded and executed by the Stage-0 bootstrap loader.

**Governance:** All kernel IDs are immutable. Version upgrades are performed by creating new seq values while preserving the original ID.

### 3.1 run_code_kernel

**Kernel ID:** `00000000-0000-4000-8000-000000000001`  
**Current Version:** seq=2  
**Invocation:** Triggered by request spans with entity_type='request', status='scheduled'

**Core Functions:**
- Advisory lock per span.id for concurrency control
- Timeout enforcement (configurable via manifest)
- Whitelist validation via Manifest governance
- Quota checking with race condition prevention (tenant-level locks)
- Execution result capture with provenance signatures

(SQL implementation provided in full blueprint)

### 3.2 observer_bot_kernel

**Kernel ID:** `00000000-0000-4000-8000-000000000002`  
**Current Version:** seq=2  
**Invocation:** Periodic execution via cron or timeline polling (EventBridge on AWS)

### 3.3 request_worker_kernel

**Kernel ID:** `00000000-0000-4000-8000-000000000003`  
**Current Version:** seq=2  
**Invocation:** Periodic polling for scheduled request spans

### 3.4 policy_agent_kernel

**Kernel ID:** `00000000-0000-4000-8000-000000000004`  
**Current Version:** seq=1  
**Invocation:** Triggered on new timeline events matching policy predicates

### 3.5 provider_exec_kernel

**Kernel ID:** `00000000-0000-4000-8000-000000000005`  
**Current Version:** seq=1  
**Invocation:** Triggered by provider_request spans (AWS Bedrock integration in P2)

---

## 14) Memory System / Sistema de Memória

> **Ver Anexo A: P3** para implementação completa com encryption e session persistence

The LogLineOS Memory System turns user facts, preferences, notes, profiles and summaries into **append-only spans** (`entity_type='memory'`) with optional **field-level encryption**, strict **RLS**, and **session-aware persistence**.

**Key Features:**
- Contract-first memory artifacts with schema validation
- Session persistence with opt-in, scoped, TTL-bound memory per conversation
- Privacy by default: consent-gated capture, field-level AES-256-GCM, RLS, redaction
- Quality promotion workflow (temporary → permanent)
- RAG with ranked retrieval and circuit breaker

---

# Anexo A: Execução 100% AWS (Automação Total)

## Propósito

Este anexo operacionaliza o Blueprint4 no ambiente AWS, sem alterar sua filosofia. Ele traduz as decisões já congeladas no Blueprint4 em fases executáveis (P0–P5), com invariantes, entregáveis e critérios de pronto.

## Premissas

- **Ledger único:** `ledger.universal_registry` em PostgreSQL (Aurora/RDS)
- **Toda mudança vira span;** toda execução nasce do ledger; idempotência por `compiled_hash/origin`
- **Stage-0 Loader** (Lambda) + API Gateway + EventBridge como plano de controle
- **"Provider Kernel"** invoca LLMs (iniciar por Bedrock); políticas de quota/circuit breaker/pactos no caminho quente

## Escopo do Anexo

**Incluído:** LogLineOS core, onboarding computável de apps, prompt system e memory.  
**Fora de escopo:** App macOS, extensão de IDE, UIs.

## Mapa de Traço (Blueprint4 → Plano AWS)

| Blueprint4 Component | AWS Phase | AWS Services |
|---------------------|-----------|--------------|
| Ledger / Universal Registry | **P0** | RDS/Aurora + schema spans + índices de deduplicação |
| Stage-0 Loader / Ingest | **P1** | POST /api/spans + agentes (onboard, smoke, promotion) via EventBridge |
| Execution / Provider Kernel | **P2** | run_code(span_id) + Bedrock (anthropic.claude-3.5) + políticas runtime |
| Onboarding computável | **P1/P3** | app_bundle, onboard_agent e bundle_template (plug-and-play) |
| Governança / Promoção | **P4** | bundle_gov (gate de promoção, aprovação, escalonamento) |
| Observabilidade / Operação | **P5** | bundle_observer_config + sugestões/mitigações |

## Fases (Resumo Executivo)

### P0: Banco + Segredo + DDL e Índices
**Critério:** Lambda acessa spans com `DB_SECRET_ARN`

**Entregáveis:**
- Amazon Aurora PostgreSQL (Multi-AZ) provisionado
- RDS Proxy configurado para conexões Lambda
- Schema `ledger.universal_registry` + view `visible_timeline` instalado
- Índices de idempotência e performance criados
- RLS habilitado com funções `app.current_user_id/tenant_id`
- Secrets Manager com credenciais do banco
- KMS keys por tenant configuradas

**Comandos:**
```bash
# Provision via CDK
cd infra/
cdk deploy DatabaseStack

# Apply migrations
cd db/
./migrate.sh apply
```

### P1: Ingest/Agents
**Critério:** Seed `app_bundle` materializa funções, políticas, prompts, memória, pactos, SLO e testes

**Entregáveis:**
- API Gateway (HTTP API) com rota POST `/api/spans`
- Lambda Stage-0 Loader configurada
- EventBridge rules para agendamento (observer, request_worker minutely)
- Seeds NDJSON importadas (kernels, policies, manifests)
- Idempotency via X-Idempotency-Key + unique indexes

**Stack:**
```typescript
// infra/stacks/api-stack.ts
const api = new HttpApi(this, 'LogLineAPI', {
  corsPreflight: {
    allowOrigins: ['*'],
    allowMethods: [CorsHttpMethod.POST, CorsHttpMethod.GET],
  },
});

const ingestHandler = new NodejsFunction(this, 'IngestHandler', {
  entry: 'functions/api/ingest/handler.ts',
  environment: {
    DB_SECRET_ARN: props.dbSecret.secretArn,
  },
});

api.addRoutes({
  path: '/api/spans',
  methods: [HttpMethod.POST],
  integration: new HttpLambdaIntegration('IngestIntegration', ingestHandler),
});
```

### P2: Execução Real
**Critério:** request → execution (Bedrock) → telemetry/assertion; pactos e quotas ativos

**Entregáveis:**
- Lambda run_code_kernel com advisory locks e timeout
- AWS Bedrock integration (anthropic.claude-3.5-sonnet)
- Policy engine com circuit breaker, throttle, slow detection
- Telemetry spans com model + compiled_hash
- Quotas tenant-level com locks para prevenir race conditions

**Provider Integration:**
```typescript
// functions/kernels/provider_exec/handler.ts
import { BedrockRuntimeClient, InvokeModelCommand } from "@aws-sdk/client-bedrock-runtime";

const bedrock = new BedrockRuntimeClient({ region: process.env.AWS_REGION });

async function invokeModel(prompt: string, model = "anthropic.claude-3-5-sonnet-20240620-v1:0") {
  const command = new InvokeModelCommand({
    modelId: model,
    body: JSON.stringify({
      anthropic_version: "bedrock-2023-05-31",
      messages: [{ role: "user", content: prompt }],
      max_tokens: 2048,
      temperature: 0.2,
    }),
  });
  
  const response = await bedrock.send(command);
  return JSON.parse(new TextDecoder().decode(response.body));
}
```

### P3: Template/Instanciação
**Critério:** `bundle_instantiation` gera suíte para um tenant, com overrides

**Entregáveis:**
- Bundle templates para onboarding de apps
- Instantiation engine com parameter substitution
- Memory system com field-level encryption (AES-256-GCM via KMS)
- Session persistence com TTL e consent management
- RAG retrieval com pgvector (opcional)

**Memory Schema:**
```sql
CREATE TABLE IF NOT EXISTS ledger.memory_embeddings (
  span_id uuid PRIMARY KEY,
  tenant_id text NOT NULL,
  dim int DEFAULT 1536,
  embedding vector(1536),
  created_at timestamptz DEFAULT now()
);

CREATE INDEX ON ledger.memory_embeddings USING ivfflat (embedding vector_cosine_ops)
  WITH (lists = 100);
```

### P4: Governança Mínima
**Critério:** Promoção bloqueada sem aprovação/checagens

**Entregáveis:**
- Approval workflow para promoção de spans
- 2-of-N signature verification para mudanças críticas
- Policy validation gates
- Rollback mechanism via versioned spans
- Audit trail com hash chains

**Governance Flow:**
```typescript
async function promoteSpan(spanId: string, approvers: string[]) {
  // Require 2-of-N signatures
  if (approvers.length < 2) {
    throw new Error("Minimum 2 approvers required");
  }
  
  // Verify signatures
  for (const approver of approvers) {
    await verifySignature(spanId, approver);
  }
  
  // Emit promotion span
  await insertSpan({
    id: randomUUID(),
    seq: 0,
    entity_type: 'promotion',
    who: `governance:promotion`,
    did: 'promoted',
    this: `span:${spanId}`,
    status: 'complete',
    related_to: [spanId],
    metadata: { approvers, promoted_at: new Date().toISOString() },
  });
}
```

### P5: Observador
**Critério:** Sugestões/alertas quando p95/custo/erro estourarem o alvo

**Entregáveis:**
- CloudWatch Dashboards com métricas chave
- Alarms para latência, erro, throttling, slow execution, quota, custo
- X-Ray distributed tracing
- Synthetics canários para smoke tests
- Cost anomaly detection
- Automated remediation via EventBridge → Lambda

**Observability Stack:**
```typescript
// Dashboards
const dashboard = new Dashboard(this, 'LogLineDashboard', {
  dashboardName: 'LogLineOS-Production',
});

dashboard.addWidgets(
  new GraphWidget({
    title: 'Execution Latency',
    left: [executionDurationMetric],
    leftYAxis: { label: 'ms' },
  }),
  new SingleValueWidget({
    title: 'Today Executions',
    metrics: [executionCountMetric],
  }),
);

// Alarms
new Alarm(this, 'HighLatencyAlarm', {
  metric: executionDurationMetric.with({ statistic: 'p95' }),
  threshold: 5000,
  evaluationPeriods: 2,
  alarmDescription: 'P95 latency > 5s',
});
```

## Invariantes (Herdados do Blueprint4)

1. **Nenhuma execução fora do ledger**
2. **Nenhuma mutação sem idempotência e assinatura**
3. **Qualquer derivação aponta para origin.{registration|bundle|template}**
4. **Spans são append-only; UPDATE/DELETE bloqueados por trigger**
5. **RLS enforçado em todas as queries**
6. **Quotas verificadas com tenant-level advisory locks**

## Integração com o Blueprint4

### Onde Colar no Documento

**Opção A (recomendada):** Colocar como "Anexo A" ao final do Blueprint4.md e, no início do Blueprint4, inserir uma nota:

> "Para execução 100% AWS e automação total, ver Anexo A."

**Opção B:** Logo após a seção de arquitetura computável do B4, com título "Anexo A (AWS)".

### Pointers Internos

No corpo do B4, onde você fala de:
- **Ledger** → Ver Anexo A: P0
- **Stage-0 Loader** → Ver Anexo A: P1
- **Provider Kernel** → Ver Anexo A: P2
- **Onboarding** → Ver Anexo A: P1/P3
- **Governança** → Ver Anexo A: P4
- **Observabilidade** → Ver Anexo A: P5

## Roadmap de Execução (Curto e Certeiro)

### Semana 1 — Infra Mínima
- CDK: VPC, Aurora PG + Proxy, KMS/Secrets, API GW/ALB, Lambdas, EventBridge
- Migra as DDL/Views/RLS/Índices do blueprint

### Semana 2 — Kernels e Manifest
- Stage-0 Loader + run_code, request_worker, policy_agent em spans
- Manifest/whitelist

### Semana 3 — APIs e Onboarding
- /api/execute, /timeline/stream, Memory API, /apps/onboard

### Semana 4 — Prompt System
- Build/Runner/Eval/Bandit + policies (circuit breaker, slow, ttl)

### Semana 5 — Observabilidade e Hardening
- Dashboards, SLOs, canários, DR, budgets
- E2E seeds e promotion de variantes estáveis

## Bootstrap Completo (Comando Único)

```bash
# From AWS CloudShell or local with AWS credentials
git clone https://github.com/your-org/loglineos-aws
cd loglineos-aws
./scripts/bootstrap.sh

# Script detecta DB_SECRET_ARN automaticamente
# Se não achar, imprime comando para setar e reexecuta
# Continua 100% hands-off após primeiro boot
```

## Já Feito (Neste Repositório)

O arquivo `loglineos-aws-starter.zip` contém:

- **Aurora PostgreSQL** + RDS Proxy + VPC
- **Lambdas:** run_code, request_worker, policy_agent, api/execute, api/memory, api/timeline/stream
- **EventBridge:** agendas minutely (workers)
- **API Gateway** (HTTP API) com rotas /api/execute, /api/memory, /api/timeline/stream
- **Migrations SQL** (ledger spans, memory, prompts, policies, views) + seeds NDJSON
- **Scripts idempotentes:** migrate.ts, seed.ts, bootstrap.sh
- **CDK stacks:** plataforma (VPC/DB/KMS/Secrets), kernels, API, eventos, pipeline
- **GitHub Actions** (opcional) para lint/build

## Como Usar (Após Deploy)

```bash
# Schedule execution
curl -X POST https://api.logline.dev/api/execute \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"span_id": "00000000-0000-4000-8000-000000000001"}'

# Store memory
curl -X POST https://api.logline.dev/api/memory \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "layer": "session",
    "type": "preference",
    "content": {"text": "User prefers dark mode"},
    "session_id": "session-uuid"
  }'

# Stream timeline
curl -N https://api.logline.dev/api/timeline/stream?tenant_id=voulezvous
```

## Próximos Upgrades (Opcionais)

- Bandit + evaluator no prompt system (variante por compiled_hash + métricas)
- SSE real por ALB + Lambda (para streams longos)
- Policies ledger-only (ttl, throttle, circuit breaker, confidence escalation) operando via policy_agent
- Pipeline CodePipeline/CodeBuild conectado ao GitHub App Agent por OIDC (git push → prod)
- Multi-region DR com Aurora Global Database
- Edge deployment com CloudFront + Lambda@Edge para baixa latência global

## Critérios de Sucesso

### P0 ✅
- [ ] Lambda conecta ao Aurora via RDS Proxy usando DB_SECRET_ARN
- [ ] Schema instalado com todas as tabelas, views, indexes, triggers
- [ ] RLS ativo e testado

### P1 ✅
- [ ] POST /api/spans aceita e persiste span assinado
- [ ] EventBridge dispara kernels minutely
- [ ] Seeds NDJSON importadas com sucesso
- [ ] Idempotency previne duplicatas

### P2 ✅
- [ ] Request → run_code → execution (Bedrock) completo em <3s (p95)
- [ ] Telemetry inclui model + compiled_hash
- [ ] Quotas impedem overuse; circuit breaker ativo

### P3 ✅
- [ ] Bundle instantiation gera app completo para tenant
- [ ] Memory com encryption funciona; session persistence ativa
- [ ] RAG retrieval retorna resultados ranqueados

### P4 ✅
- [ ] Promoção requer 2-of-N signatures
- [ ] Rollback funciona via versioned spans
- [ ] Audit trail verificável

### P5 ✅
- [ ] Dashboards mostram métricas em tempo real
- [ ] Alarms disparam em violações de SLO
- [ ] Canários validam funcionalidade 24/7
- [ ] Cost anomalies detectadas automaticamente

---

## Sugerido para Commit

```
docs: anexar "Anexo A — Execução 100% AWS (Automação Total)"
- Concretiza Blueprint4 em P0–P5 no plano AWS
- Mantém invariantes de spans/idempotência/assinatura
- Roadmap executável com critérios claros de sucesso
```

---

**Fim do Anexo A**

---

## Retornar ao Índice Principal

[↑ Voltar ao Índice](#table-of-contents)

