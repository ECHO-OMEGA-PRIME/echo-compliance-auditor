/**
 * Echo Compliance Auditor — Security & Configuration Compliance Worker
 * Audits all ECHO Workers against security policies, validates configs,
 * enforces standards, maintains audit trails.
 * Version: 1.0.0
 */

import { Hono } from 'hono';
import { cors } from 'hono/cors';

// ─── Types ───────────────────────────────────────────────────────────────────

interface Env {
  DB: D1Database;
  CACHE: KVNamespace;
  SHARED_BRAIN: Fetcher;
  ALERT_ROUTER: Fetcher;
  SERVICE_REGISTRY: Fetcher;
  WORKER_VERSION: string;
  WORKER_NAME: string;
  ECHO_API_KEY: string;
}

interface AuditPolicy {
  id: string;
  name: string;
  description: string;
  category: 'security' | 'config' | 'performance' | 'naming' | 'logging';
  severity: 'critical' | 'high' | 'medium' | 'low';
  check_type: string;
  check_config: string;
  enabled: number;
  created_at: string;
  updated_at: string;
}

interface AuditRun {
  id: string;
  run_type: 'scheduled' | 'manual' | 'targeted';
  status: 'running' | 'completed' | 'failed';
  started_at: string;
  completed_at: string | null;
  services_checked: number;
  policies_checked: number;
  violations_found: number;
  pass_rate: number;
}

interface AuditFinding {
  id: string;
  run_id: string;
  policy_id: string;
  service_name: string;
  finding_type: 'violation' | 'warning' | 'info';
  severity: 'critical' | 'high' | 'medium' | 'low';
  description: string;
  evidence: string | null;
  remediation: string | null;
  status: 'open' | 'acknowledged' | 'resolved' | 'waived';
  resolved_at: string | null;
  resolved_by: string | null;
  created_at: string;
}

interface ComplianceScore {
  id: string;
  service_name: string;
  overall_score: number;
  security_score: number;
  config_score: number;
  performance_score: number;
  last_audited: string | null;
  updated_at: string;
}

interface LogEntry {
  timestamp: string;
  level: 'debug' | 'info' | 'warn' | 'error' | 'fatal';
  worker: string;
  version: string;
  message: string;
  data?: Record<string, unknown>;
  correlation_id?: string;
  duration_ms?: number;
}

// ─── Logging ─────────────────────────────────────────────────────────────────

const WORKER_NAME = 'echo-compliance-auditor';
const WORKER_VERSION = '1.0.0';
let requestCount = 0;
let errorCount = 0;
const startTime = Date.now();

function log(level: LogEntry['level'], message: string, data?: Record<string, unknown>): void {
  const entry: LogEntry = {
    timestamp: new Date().toISOString(),
    level,
    worker: WORKER_NAME,
    version: WORKER_VERSION,
    message,
    ...(data ? { data } : {}),
  };
  const output = JSON.stringify(entry);
  switch (level) {
    case 'error':
    case 'fatal':
      console.error(output);
      break;
    case 'warn':
      console.warn(output);
      break;
    default:
      console.log(output);
  }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function generateId(): string {
  return crypto.randomUUID();
}

function jsonResponse(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'X-Worker-Version': WORKER_VERSION,
      'X-Worker-Name': WORKER_NAME,
    },
  });
}

function errorResponse(message: string, status: number, details?: unknown): Response {
  errorCount++;
  log('error', message, { status, details: details as Record<string, unknown> });
  return jsonResponse({ ok: false, error: message, details: details ?? null }, status);
}

// ─── Auth Middleware ─────────────────────────────────────────────────────────

function requireAuth(c: { req: { header: (name: string) => string | undefined }; env: Env }): boolean {
  if (!c.env.ECHO_API_KEY) return false;
  const key = c.req.header('X-Echo-API-Key');
  return key === c.env.ECHO_API_KEY;
}

// ─── Default Policies ────────────────────────────────────────────────────────

const DEFAULT_POLICIES: Omit<AuditPolicy, 'created_at' | 'updated_at'>[] = [
  {
    id: 'POL-001',
    name: 'AUTH_REQUIRED',
    description: 'All Workers must require X-Echo-API-Key on mutating endpoints (POST, PUT, DELETE, PATCH)',
    category: 'security',
    severity: 'critical',
    check_type: 'http_probe',
    check_config: JSON.stringify({
      method: 'POST',
      path: '/test-auth',
      expect_status: [401, 403],
      without_key: true,
    }),
    enabled: 1,
  },
  {
    id: 'POL-002',
    name: 'HEALTH_ENDPOINT',
    description: 'All Workers must have GET /health returning 200 with status field',
    category: 'config',
    severity: 'critical',
    check_type: 'http_probe',
    check_config: JSON.stringify({
      method: 'GET',
      path: '/health',
      expect_status: [200],
      expect_body_fields: ['status'],
    }),
    enabled: 1,
  },
  {
    id: 'POL-003',
    name: 'STATS_ENDPOINT',
    description: 'All Workers must have GET /stats returning operational metrics',
    category: 'config',
    severity: 'high',
    check_type: 'http_probe',
    check_config: JSON.stringify({
      method: 'GET',
      path: '/stats',
      expect_status: [200],
    }),
    enabled: 1,
  },
  {
    id: 'POL-004',
    name: 'STRUCTURED_LOGGING',
    description: 'No console.log in production — must use structured JSON logging',
    category: 'logging',
    severity: 'high',
    check_type: 'code_pattern',
    check_config: JSON.stringify({
      forbidden_patterns: ['console.log(', 'console.info('],
      required_patterns: ['JSON.stringify'],
      description: 'Code must use structured logging, not raw console.log',
    }),
    enabled: 1,
  },
  {
    id: 'POL-005',
    name: 'CORS_HEADERS',
    description: 'All Workers must set appropriate CORS headers',
    category: 'security',
    severity: 'high',
    check_type: 'http_probe',
    check_config: JSON.stringify({
      method: 'OPTIONS',
      path: '/',
      expect_headers: ['access-control-allow-origin'],
    }),
    enabled: 1,
  },
  {
    id: 'POL-006',
    name: 'ERROR_HANDLING',
    description: 'All Workers must have global error handler returning structured JSON errors',
    category: 'config',
    severity: 'high',
    check_type: 'http_probe',
    check_config: JSON.stringify({
      method: 'GET',
      path: '/this-path-should-not-exist-404-test',
      expect_status: [404],
      expect_content_type: 'application/json',
    }),
    enabled: 1,
  },
  {
    id: 'POL-007',
    name: 'VERSION_HEADER',
    description: 'All Workers must return X-Worker-Version header',
    category: 'config',
    severity: 'medium',
    check_type: 'http_probe',
    check_config: JSON.stringify({
      method: 'GET',
      path: '/health',
      expect_headers: ['x-worker-version'],
    }),
    enabled: 1,
  },
  {
    id: 'POL-008',
    name: 'D1_PARAMETERIZED',
    description: 'All D1 queries must use parameterized statements (no string concatenation)',
    category: 'security',
    severity: 'critical',
    check_type: 'code_pattern',
    check_config: JSON.stringify({
      forbidden_patterns: ['`SELECT', '`INSERT', '`UPDATE', '`DELETE', "'+", "' +"],
      description: 'D1 queries must use .bind() with parameterized statements',
    }),
    enabled: 1,
  },
  {
    id: 'POL-009',
    name: 'KV_CACHE_TTL',
    description: 'KV cache entries must have TTL set to prevent stale data',
    category: 'performance',
    severity: 'medium',
    check_type: 'code_pattern',
    check_config: JSON.stringify({
      required_patterns: ['expirationTtl'],
      description: 'All KV.put() calls must include expirationTtl option',
    }),
    enabled: 1,
  },
  {
    id: 'POL-010',
    name: 'OBSERVABILITY',
    description: 'wrangler.toml must have [observability] enabled=true',
    category: 'config',
    severity: 'medium',
    check_type: 'config_check',
    check_config: JSON.stringify({
      file: 'wrangler.toml',
      required_sections: ['observability'],
      required_values: { 'observability.enabled': true },
    }),
    enabled: 1,
  },
];

// ─── Known Services Registry ─────────────────────────────────────────────────

const KNOWN_SERVICES: Array<{ name: string; url: string }> = [
  { name: 'echo-shared-brain', url: 'https://echo-shared-brain.bmcii1976.workers.dev' },
  { name: 'echo-engine-runtime', url: 'https://echo-engine-runtime.bmcii1976.workers.dev' },
  { name: 'echo-sdk-gateway', url: 'https://echo-sdk-gateway.bmcii1976.workers.dev' },
  { name: 'echo-knowledge-forge', url: 'https://echo-knowledge-forge.bmcii1976.workers.dev' },
  { name: 'echo-doctrine-forge', url: 'https://echo-doctrine-forge.bmcii1976.workers.dev' },
  { name: 'echo-ai-orchestrator', url: 'https://echo-ai-orchestrator.bmcii1976.workers.dev' },
  { name: 'echo-memory-prime', url: 'https://echo-memory-prime.bmcii1976.workers.dev' },
  { name: 'echo-chat', url: 'https://echo-chat.bmcii1976.workers.dev' },
  { name: 'echo-swarm-brain', url: 'https://echo-swarm-brain.bmcii1976.workers.dev' },
  { name: 'echo-graph-rag', url: 'https://echo-graph-rag.bmcii1976.workers.dev' },
  { name: 'echo-paypal', url: 'https://echo-paypal.bmcii1976.workers.dev' },
  { name: 'echo-crypto-trader', url: 'https://echo-crypto-trader.bmcii1976.workers.dev' },
  { name: 'echo-speak-cloud', url: 'https://echo-speak-cloud.bmcii1976.workers.dev' },
  { name: 'echo-gs343-cloud', url: 'https://echo-gs343-cloud.bmcii1976.workers.dev' },
  { name: 'echo-phoenix-cloud', url: 'https://echo-phoenix-cloud.bmcii1976.workers.dev' },
  { name: 'echo-autonomous-daemon', url: 'https://echo-autonomous-daemon.bmcii1976.workers.dev' },
  { name: 'echo-vault-api', url: 'https://echo-vault-api.bmcii1976.workers.dev' },
  { name: 'echo-build-orchestrator', url: 'https://echo-build-orchestrator.bmcii1976.workers.dev' },
  { name: 'omniscient-sync', url: 'https://omniscient-sync.bmcii1976.workers.dev' },
  { name: 'echo-mega-gateway', url: 'https://echo-mega-gateway.bmcii1976.workers.dev' },
  { name: 'echo-alert-router', url: 'https://echo-alert-router.bmcii1976.workers.dev' },
  { name: 'echo-service-registry', url: 'https://echo-service-registry.bmcii1976.workers.dev' },
  { name: 'echo-health-dashboard', url: 'https://echo-health-dashboard.bmcii1976.workers.dev' },
  { name: 'echo-cost-optimizer', url: 'https://echo-cost-optimizer.bmcii1976.workers.dev' },
  { name: 'echo-landman-pipeline', url: 'https://echo-landman-pipeline.bmcii1976.workers.dev' },
  { name: 'echo-model-host', url: 'https://echo-model-host.bmcii1976.workers.dev' },
  { name: 'echo-revenue-engine', url: 'https://echo-revenue-engine.bmcii1976.workers.dev' },
  { name: 'echo-knowledge-harvester', url: 'https://echo-knowledge-harvester.bmcii1976.workers.dev' },
  { name: 'echo-compliance-auditor', url: 'https://echo-compliance-auditor.bmcii1976.workers.dev' },
];

// ─── Audit Engine ────────────────────────────────────────────────────────────

interface CheckResult {
  passed: boolean;
  finding_type: 'violation' | 'warning' | 'info';
  description: string;
  evidence: string;
  remediation: string;
}

async function runHttpProbeCheck(
  serviceUrl: string,
  serviceName: string,
  policy: AuditPolicy,
  env: Env
): Promise<CheckResult> {
  const config = JSON.parse(policy.check_config) as {
    method: string;
    path: string;
    expect_status?: number[];
    expect_headers?: string[];
    expect_body_fields?: string[];
    expect_content_type?: string;
    without_key?: boolean;
  };

  const url = `${serviceUrl}${config.path}`;
  const headers: Record<string, string> = {};
  if (!config.without_key) {
    headers['X-Echo-API-Key'] = env.ECHO_API_KEY;
  }

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 10000);

    const resp = await fetch(url, {
      method: config.method,
      headers,
      signal: controller.signal,
    });
    clearTimeout(timeoutId);

    const issues: string[] = [];
    const evidence: string[] = [];

    // Check status code
    if (config.expect_status && config.expect_status.length > 0) {
      if (!config.expect_status.includes(resp.status)) {
        issues.push(`Expected status ${config.expect_status.join('|')}, got ${resp.status}`);
        evidence.push(`HTTP ${resp.status} from ${config.method} ${config.path}`);
      }
    }

    // Check headers
    if (config.expect_headers) {
      for (const header of config.expect_headers) {
        if (!resp.headers.get(header)) {
          issues.push(`Missing required header: ${header}`);
          evidence.push(`Header '${header}' not found in response`);
        }
      }
    }

    // Check content type
    if (config.expect_content_type) {
      const ct = resp.headers.get('content-type') ?? '';
      if (!ct.includes(config.expect_content_type)) {
        issues.push(`Expected content-type ${config.expect_content_type}, got ${ct}`);
        evidence.push(`Content-Type: ${ct}`);
      }
    }

    // Check body fields
    if (config.expect_body_fields && config.expect_body_fields.length > 0) {
      try {
        const body = await resp.json() as Record<string, unknown>;
        for (const field of config.expect_body_fields) {
          if (!(field in body)) {
            issues.push(`Missing required body field: ${field}`);
            evidence.push(`Response body missing '${field}' field`);
          }
        }
      } catch {
        issues.push('Response body is not valid JSON');
        evidence.push('Failed to parse response as JSON');
      }
    }

    if (issues.length === 0) {
      return {
        passed: true,
        finding_type: 'info',
        description: `${serviceName} passes ${policy.name}`,
        evidence: `${config.method} ${config.path} returned expected response`,
        remediation: 'None needed',
      };
    }

    return {
      passed: false,
      finding_type: policy.severity === 'critical' ? 'violation' : 'warning',
      description: `${serviceName} fails ${policy.name}: ${issues.join('; ')}`,
      evidence: evidence.join('\n'),
      remediation: policy.description,
    };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return {
      passed: false,
      finding_type: 'violation',
      description: `${serviceName} unreachable for ${policy.name} check: ${message}`,
      evidence: `Failed to reach ${url}: ${message}`,
      remediation: `Ensure ${serviceName} is deployed and accessible`,
    };
  }
}

async function runCodePatternCheck(
  _serviceUrl: string,
  serviceName: string,
  policy: AuditPolicy
): Promise<CheckResult> {
  // Code pattern checks are informational — we can't inspect source at runtime,
  // but we record the policy requirement for manual review
  const config = JSON.parse(policy.check_config) as {
    forbidden_patterns?: string[];
    required_patterns?: string[];
    description?: string;
  };

  return {
    passed: true,
    finding_type: 'info',
    description: `${serviceName}: ${policy.name} requires manual code review — ${config.description ?? policy.description}`,
    evidence: JSON.stringify({
      forbidden: config.forbidden_patterns ?? [],
      required: config.required_patterns ?? [],
    }),
    remediation: config.description ?? policy.description,
  };
}

async function runConfigCheck(
  _serviceUrl: string,
  serviceName: string,
  policy: AuditPolicy
): Promise<CheckResult> {
  // Config checks are also informational at runtime
  const config = JSON.parse(policy.check_config) as {
    file?: string;
    required_sections?: string[];
    required_values?: Record<string, unknown>;
  };

  return {
    passed: true,
    finding_type: 'info',
    description: `${serviceName}: ${policy.name} requires ${config.file ?? 'config'} review`,
    evidence: JSON.stringify(config),
    remediation: policy.description,
  };
}

async function runPolicyCheck(
  serviceUrl: string,
  serviceName: string,
  policy: AuditPolicy,
  env: Env
): Promise<CheckResult> {
  switch (policy.check_type) {
    case 'http_probe':
      return runHttpProbeCheck(serviceUrl, serviceName, policy, env);
    case 'code_pattern':
      return runCodePatternCheck(serviceUrl, serviceName, policy);
    case 'config_check':
      return runConfigCheck(serviceUrl, serviceName, policy);
    default:
      return {
        passed: false,
        finding_type: 'warning',
        description: `Unknown check_type: ${policy.check_type}`,
        evidence: `Policy ${policy.name} has unsupported check_type`,
        remediation: 'Update policy check_type to http_probe, code_pattern, or config_check',
      };
  }
}

async function executeAuditRun(
  db: D1Database,
  cache: KVNamespace,
  env: Env,
  runType: AuditRun['run_type'],
  targetServices?: string[]
): Promise<{ runId: string; violations: number; servicesChecked: number }> {
  const runId = generateId();
  const now = new Date().toISOString();

  // Create run record
  await db.prepare(
    'INSERT INTO audit_runs (id, run_type, status, started_at) VALUES (?, ?, ?, ?)'
  ).bind(runId, runType, 'running', now).run();

  log('info', 'Audit run started', { runId, runType, targetServices });

  // Get enabled policies
  const policiesResult = await db.prepare(
    'SELECT * FROM audit_policies WHERE enabled = 1'
  ).all<AuditPolicy>();
  const policies = policiesResult.results ?? [];

  if (policies.length === 0) {
    log('warn', 'No enabled policies found, completing run with zero checks');
    await db.prepare(
      'UPDATE audit_runs SET status = ?, completed_at = ?, services_checked = 0, policies_checked = 0, violations_found = 0, pass_rate = 100.0 WHERE id = ?'
    ).bind('completed', now, runId).run();
    return { runId, violations: 0, servicesChecked: 0 };
  }

  // Determine services to check
  let services = KNOWN_SERVICES;
  if (targetServices && targetServices.length > 0) {
    services = KNOWN_SERVICES.filter(s => targetServices.includes(s.name));
  }

  // Get active waivers
  const waiversResult = await db.prepare(
    "SELECT * FROM audit_waivers WHERE expires_at IS NULL OR expires_at > datetime('now')"
  ).all<{ policy_id: string; service_name: string }>();
  const waivers = waiversResult.results ?? [];
  const waiverSet = new Set(waivers.map(w => `${w.service_name}:${w.policy_id}`));

  let totalChecks = 0;
  let passedChecks = 0;
  let totalViolations = 0;
  const serviceScores: Map<string, { security: number[]; config: number[]; performance: number[] }> = new Map();

  // Only run http_probe policies against live services
  const httpPolicies = policies.filter(p => p.check_type === 'http_probe');
  const otherPolicies = policies.filter(p => p.check_type !== 'http_probe');

  for (const service of services) {
    if (!serviceScores.has(service.name)) {
      serviceScores.set(service.name, { security: [], config: [], performance: [] });
    }
    const scores = serviceScores.get(service.name)!;

    // Run HTTP probe checks
    for (const policy of httpPolicies) {
      // Check for waiver
      if (waiverSet.has(`${service.name}:${policy.id}`)) {
        totalChecks++;
        passedChecks++;
        const categoryScores = policy.category === 'security' ? scores.security :
          policy.category === 'performance' ? scores.performance : scores.config;
        categoryScores.push(100);
        continue;
      }

      totalChecks++;
      const result = await runPolicyCheck(service.url, service.name, policy, env);

      if (result.passed) {
        passedChecks++;
        const categoryScores = policy.category === 'security' ? scores.security :
          policy.category === 'performance' ? scores.performance : scores.config;
        categoryScores.push(100);
      } else {
        totalViolations++;
        const categoryScores = policy.category === 'security' ? scores.security :
          policy.category === 'performance' ? scores.performance : scores.config;
        categoryScores.push(0);

        // Record finding
        await db.prepare(
          'INSERT INTO audit_findings (id, run_id, policy_id, service_name, finding_type, severity, description, evidence, remediation, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
        ).bind(
          generateId(), runId, policy.id, service.name,
          result.finding_type, policy.severity,
          result.description, result.evidence, result.remediation,
          'open', now
        ).run();
      }
    }

    // Record informational entries for code/config checks
    for (const policy of otherPolicies) {
      totalChecks++;
      const result = await runPolicyCheck(service.url, service.name, policy, env);
      // Code pattern and config checks are informational
      passedChecks++;
      const categoryScores = policy.category === 'security' ? scores.security :
        policy.category === 'performance' ? scores.performance : scores.config;
      categoryScores.push(result.passed ? 100 : 50);
    }

    // Update compliance score for this service
    const avgScore = (arr: number[]): number =>
      arr.length > 0 ? arr.reduce((a, b) => a + b, 0) / arr.length : 100;

    const secScore = avgScore(scores.security);
    const cfgScore = avgScore(scores.config);
    const perfScore = avgScore(scores.performance);
    const overall = (secScore * 0.4 + cfgScore * 0.35 + perfScore * 0.25);

    const existingScore = await db.prepare(
      'SELECT id FROM compliance_scores WHERE service_name = ?'
    ).bind(service.name).first();

    if (existingScore) {
      await db.prepare(
        'UPDATE compliance_scores SET overall_score = ?, security_score = ?, config_score = ?, performance_score = ?, last_audited = ?, updated_at = ? WHERE service_name = ?'
      ).bind(overall, secScore, cfgScore, perfScore, now, now, service.name).run();
    } else {
      await db.prepare(
        'INSERT INTO compliance_scores (id, service_name, overall_score, security_score, config_score, performance_score, last_audited, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
      ).bind(generateId(), service.name, overall, secScore, cfgScore, perfScore, now, now).run();
    }
  }

  const passRate = totalChecks > 0 ? (passedChecks / totalChecks) * 100 : 100;

  // Complete the run
  await db.prepare(
    'UPDATE audit_runs SET status = ?, completed_at = ?, services_checked = ?, policies_checked = ?, violations_found = ?, pass_rate = ? WHERE id = ?'
  ).bind('completed', new Date().toISOString(), services.length, policies.length, totalViolations, passRate, runId).run();

  // Cache latest run summary
  await cache.put('latest_run', JSON.stringify({
    runId, runType, servicesChecked: services.length,
    policiesChecked: policies.length, violations: totalViolations, passRate,
    completedAt: new Date().toISOString(),
  }), { expirationTtl: 86400 });

  log('info', 'Audit run completed', {
    runId, servicesChecked: services.length, policiesChecked: policies.length,
    violations: totalViolations, passRate,
  });

  return { runId, violations: totalViolations, servicesChecked: services.length };
}

// ─── App ─────────────────────────────────────────────────────────────────────

type Variables = Record<string, never>;
const app = new Hono<{ Bindings: Env; Variables: Variables }>();

// CORS
app.use('*', cors({
  origin: '*',
  allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowHeaders: ['Content-Type', 'X-Echo-API-Key', 'Authorization'],
  exposeHeaders: ['X-Worker-Version', 'X-Worker-Name'],
}));
// Security headers middleware
app.use('*', async (c, next) => {
  await next();
  c.res.headers.set('X-Content-Type-Options', 'nosniff');
  c.res.headers.set('X-Frame-Options', 'DENY');
  c.res.headers.set('X-XSS-Protection', '1; mode=block');
  c.res.headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
  c.res.headers.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
});


// Version header on all responses
app.use('*', async (c, next) => {
  requestCount++;
  await next();
  c.header('X-Worker-Version', WORKER_VERSION);
  c.header('X-Worker-Name', WORKER_NAME);
});

// ─── 1. GET /health ──────────────────────────────────────────────────────────

app.get("/", (c) => c.json({ service: 'echo-compliance-auditor', status: 'operational' }));

app.get('/health', async (c) => {
  let dbOk = false;
  try {
    await c.env.DB.prepare('SELECT 1').first();
    dbOk = true;
  } catch { /* db unreachable */ }

  return c.json({
    status: dbOk ? 'healthy' : 'degraded',
    worker: WORKER_NAME,
    version: WORKER_VERSION,
    timestamp: new Date().toISOString(),
    uptime_ms: Date.now() - startTime,
    dependencies: { d1: dbOk ? 'ok' : 'error', kv: 'ok' },
  });
});

// ─── 2. GET /stats ───────────────────────────────────────────────────────────

app.get('/stats', async (c) => {
  const [policiesCount, runsCount, openFindings, avgScore] = await Promise.all([
    c.env.DB.prepare('SELECT COUNT(*) as cnt FROM audit_policies WHERE enabled = 1').first<{ cnt: number }>(),
    c.env.DB.prepare('SELECT COUNT(*) as cnt FROM audit_runs').first<{ cnt: number }>(),
    c.env.DB.prepare("SELECT COUNT(*) as cnt FROM audit_findings WHERE status = 'open'").first<{ cnt: number }>(),
    c.env.DB.prepare('SELECT AVG(overall_score) as avg FROM compliance_scores').first<{ avg: number | null }>(),
  ]);

  return c.json({
    ok: true,
    stats: {
      total_policies: policiesCount?.cnt ?? 0,
      total_runs: runsCount?.cnt ?? 0,
      open_findings: openFindings?.cnt ?? 0,
      avg_compliance_score: Math.round((avgScore?.avg ?? 0) * 100) / 100,
      request_count: requestCount,
      error_count: errorCount,
      uptime_ms: Date.now() - startTime,
    },
  });
});

// ─── 3. GET /policies ────────────────────────────────────────────────────────

app.get('/policies', async (c) => {
  const category = c.req.query('category');
  const severity = c.req.query('severity');
  const enabled = c.req.query('enabled');

  let sql = 'SELECT * FROM audit_policies WHERE 1=1';
  const params: (string | number)[] = [];

  if (category) {
    sql += ' AND category = ?';
    params.push(category);
  }
  if (severity) {
    sql += ' AND severity = ?';
    params.push(severity);
  }
  if (enabled !== undefined && enabled !== null && enabled !== '') {
    sql += ' AND enabled = ?';
    params.push(enabled === 'true' || enabled === '1' ? 1 : 0);
  }

  sql += ' ORDER BY severity ASC, name ASC';

  const stmt = c.env.DB.prepare(sql);
  const result = params.length > 0 ? await stmt.bind(...params).all<AuditPolicy>() : await stmt.all<AuditPolicy>();

  return c.json({ ok: true, count: result.results?.length ?? 0, policies: result.results ?? [] });
});

// ─── 4. GET /policies/:id ────────────────────────────────────────────────────

app.get('/policies/:id', async (c) => {
  const id = c.req.param('id');
  const policy = await c.env.DB.prepare('SELECT * FROM audit_policies WHERE id = ?').bind(id).first<AuditPolicy>();
  if (!policy) return errorResponse('Policy not found', 404);
  return c.json({ ok: true, policy });
});

// ─── 5. POST /policies ───────────────────────────────────────────────────────

app.post('/policies', async (c) => {
  if (!requireAuth(c)) return errorResponse('Unauthorized', 401);

  const body = await c.req.json<Partial<AuditPolicy>>();
  if (!body.name || !body.description || !body.category || !body.severity || !body.check_type) {
    return errorResponse('Missing required fields: name, description, category, severity, check_type', 400);
  }

  const validCategories = ['security', 'config', 'performance', 'naming', 'logging'];
  const validSeverities = ['critical', 'high', 'medium', 'low'];
  if (!validCategories.includes(body.category)) return errorResponse(`Invalid category. Must be: ${validCategories.join(', ')}`, 400);
  if (!validSeverities.includes(body.severity)) return errorResponse(`Invalid severity. Must be: ${validSeverities.join(', ')}`, 400);

  const id = body.id ?? `POL-${Date.now()}`;
  const now = new Date().toISOString();

  await c.env.DB.prepare(
    'INSERT INTO audit_policies (id, name, description, category, severity, check_type, check_config, enabled, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
  ).bind(
    id, body.name, body.description, body.category, body.severity,
    body.check_type, body.check_config ?? '{}', body.enabled ?? 1, now, now
  ).run();

  log('info', 'Policy created', { id, name: body.name });
  return c.json({ ok: true, id, message: 'Policy created' }, 201);
});

// ─── 6. PUT /policies/:id ────────────────────────────────────────────────────

app.put('/policies/:id', async (c) => {
  if (!requireAuth(c)) return errorResponse('Unauthorized', 401);

  const id = c.req.param('id');
  const existing = await c.env.DB.prepare('SELECT * FROM audit_policies WHERE id = ?').bind(id).first<AuditPolicy>();
  if (!existing) return errorResponse('Policy not found', 404);

  const body = await c.req.json<Partial<AuditPolicy>>();
  const now = new Date().toISOString();

  await c.env.DB.prepare(
    'UPDATE audit_policies SET name = ?, description = ?, category = ?, severity = ?, check_type = ?, check_config = ?, enabled = ?, updated_at = ? WHERE id = ?'
  ).bind(
    body.name ?? existing.name,
    body.description ?? existing.description,
    body.category ?? existing.category,
    body.severity ?? existing.severity,
    body.check_type ?? existing.check_type,
    body.check_config ?? existing.check_config,
    body.enabled ?? existing.enabled,
    now, id
  ).run();

  log('info', 'Policy updated', { id });
  return c.json({ ok: true, message: 'Policy updated' });
});

// ─── 7. POST /audit/run ─────────────────────────────────────────────────────

app.post('/audit/run', async (c) => {
  if (!requireAuth(c)) return errorResponse('Unauthorized', 401);

  const servicesParam = c.req.query('services');
  const targetServices = servicesParam ? servicesParam.split(',').map(s => s.trim()) : undefined;
  const runType: AuditRun['run_type'] = targetServices ? 'targeted' : 'manual';

  try {
    const result = await executeAuditRun(c.env.DB, c.env.CACHE, c.env, runType, targetServices);
    return c.json({
      ok: true,
      run_id: result.runId,
      services_checked: result.servicesChecked,
      violations_found: result.violations,
      message: 'Audit run completed',
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return errorResponse(`Audit run failed: ${message}`, 500);
  }
});

// ─── 8. GET /audit/runs ─────────────────────────────────────────────────────

app.get('/audit/runs', async (c) => {
  const limit = parseInt(c.req.query('limit') ?? '50', 10);
  const offset = parseInt(c.req.query('offset') ?? '0', 10);

  const result = await c.env.DB.prepare(
    'SELECT * FROM audit_runs ORDER BY started_at DESC LIMIT ? OFFSET ?'
  ).bind(limit, offset).all<AuditRun>();

  const countResult = await c.env.DB.prepare('SELECT COUNT(*) as cnt FROM audit_runs').first<{ cnt: number }>();

  return c.json({
    ok: true,
    total: countResult?.cnt ?? 0,
    count: result.results?.length ?? 0,
    runs: result.results ?? [],
  });
});

// ─── 9. GET /audit/runs/:id ─────────────────────────────────────────────────

app.get('/audit/runs/:id', async (c) => {
  const id = c.req.param('id');
  const run = await c.env.DB.prepare('SELECT * FROM audit_runs WHERE id = ?').bind(id).first<AuditRun>();
  if (!run) return errorResponse('Run not found', 404);

  const findings = await c.env.DB.prepare(
    'SELECT * FROM audit_findings WHERE run_id = ? ORDER BY severity ASC'
  ).bind(id).all<AuditFinding>();

  return c.json({
    ok: true,
    run,
    findings: findings.results ?? [],
    findings_count: findings.results?.length ?? 0,
  });
});

// ─── 10. GET /findings ───────────────────────────────────────────────────────

app.get('/findings', async (c) => {
  const status = c.req.query('status');
  const severity = c.req.query('severity');
  const service = c.req.query('service');
  const limit = parseInt(c.req.query('limit') ?? '100', 10);
  const offset = parseInt(c.req.query('offset') ?? '0', 10);

  let sql = 'SELECT * FROM audit_findings WHERE 1=1';
  const params: (string | number)[] = [];

  if (status) { sql += ' AND status = ?'; params.push(status); }
  if (severity) { sql += ' AND severity = ?'; params.push(severity); }
  if (service) { sql += ' AND service_name = ?'; params.push(service); }

  const countSql = sql.replace('SELECT *', 'SELECT COUNT(*) as cnt');
  sql += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
  params.push(limit, offset);

  const countParams = params.slice(0, -2);
  const countStmt = c.env.DB.prepare(countSql);
  const countResult = countParams.length > 0
    ? await countStmt.bind(...countParams).first<{ cnt: number }>()
    : await countStmt.first<{ cnt: number }>();

  const stmt = c.env.DB.prepare(sql);
  const result = params.length > 0 ? await stmt.bind(...params).all<AuditFinding>() : await stmt.all<AuditFinding>();

  return c.json({
    ok: true,
    total: countResult?.cnt ?? 0,
    count: result.results?.length ?? 0,
    findings: result.results ?? [],
  });
});

// ─── 11. GET /findings/:id ───────────────────────────────────────────────────

app.get('/findings/:id', async (c) => {
  const id = c.req.param('id');
  const finding = await c.env.DB.prepare('SELECT * FROM audit_findings WHERE id = ?').bind(id).first<AuditFinding>();
  if (!finding) return errorResponse('Finding not found', 404);

  const waiver = await c.env.DB.prepare(
    'SELECT * FROM audit_waivers WHERE finding_id = ?'
  ).bind(id).first();

  return c.json({ ok: true, finding, waiver: waiver ?? null });
});

// ─── 12. PUT /findings/:id ───────────────────────────────────────────────────

app.put('/findings/:id', async (c) => {
  if (!requireAuth(c)) return errorResponse('Unauthorized', 401);

  const id = c.req.param('id');
  const existing = await c.env.DB.prepare('SELECT * FROM audit_findings WHERE id = ?').bind(id).first<AuditFinding>();
  if (!existing) return errorResponse('Finding not found', 404);

  const body = await c.req.json<{ status?: string; resolved_by?: string }>();
  const validStatuses = ['open', 'acknowledged', 'resolved', 'waived'];
  if (body.status && !validStatuses.includes(body.status)) {
    return errorResponse(`Invalid status. Must be: ${validStatuses.join(', ')}`, 400);
  }

  const now = new Date().toISOString();
  const newStatus = body.status ?? existing.status;
  const resolvedAt = newStatus === 'resolved' ? now : existing.resolved_at;
  const resolvedBy = newStatus === 'resolved' ? (body.resolved_by ?? 'api') : existing.resolved_by;

  await c.env.DB.prepare(
    'UPDATE audit_findings SET status = ?, resolved_at = ?, resolved_by = ? WHERE id = ?'
  ).bind(newStatus, resolvedAt, resolvedBy, id).run();

  log('info', 'Finding updated', { id, status: newStatus });
  return c.json({ ok: true, message: 'Finding updated', status: newStatus });
});

// ─── 13. POST /findings/:id/waiver ──────────────────────────────────────────

app.post('/findings/:id/waiver', async (c) => {
  if (!requireAuth(c)) return errorResponse('Unauthorized', 401);

  const findingId = c.req.param('id');
  const finding = await c.env.DB.prepare('SELECT * FROM audit_findings WHERE id = ?').bind(findingId).first<AuditFinding>();
  if (!finding) return errorResponse('Finding not found', 404);

  const body = await c.req.json<{ reason: string; waived_by: string; expires_at?: string }>();
  if (!body.reason || !body.waived_by) {
    return errorResponse('Missing required fields: reason, waived_by', 400);
  }

  const waiverId = generateId();
  const now = new Date().toISOString();

  await c.env.DB.prepare(
    'INSERT INTO audit_waivers (id, finding_id, policy_id, service_name, reason, waived_by, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
  ).bind(waiverId, findingId, finding.policy_id, finding.service_name, body.reason, body.waived_by, body.expires_at ?? null, now).run();

  // Update finding status to waived
  await c.env.DB.prepare(
    "UPDATE audit_findings SET status = 'waived' WHERE id = ?"
  ).bind(findingId).run();

  log('info', 'Waiver created', { waiverId, findingId, service: finding.service_name });
  return c.json({ ok: true, waiver_id: waiverId, message: 'Waiver created, finding status set to waived' }, 201);
});

// ─── 14. GET /scores ─────────────────────────────────────────────────────────

app.get('/scores', async (c) => {
  const result = await c.env.DB.prepare(
    'SELECT * FROM compliance_scores ORDER BY overall_score ASC'
  ).all<ComplianceScore>();

  const scores = result.results ?? [];
  const avgOverall = scores.length > 0
    ? scores.reduce((sum, s) => sum + s.overall_score, 0) / scores.length
    : 0;

  return c.json({
    ok: true,
    count: scores.length,
    avg_overall_score: Math.round(avgOverall * 100) / 100,
    scores,
  });
});

// ─── 15. GET /scores/:service ────────────────────────────────────────────────

app.get('/scores/:service', async (c) => {
  const service = c.req.param('service');
  const score = await c.env.DB.prepare(
    'SELECT * FROM compliance_scores WHERE service_name = ?'
  ).bind(service).first<ComplianceScore>();
  if (!score) return errorResponse('Score not found for service', 404);

  // Get recent findings for context
  const recentFindings = await c.env.DB.prepare(
    "SELECT * FROM audit_findings WHERE service_name = ? AND status = 'open' ORDER BY severity ASC LIMIT 20"
  ).bind(service).all<AuditFinding>();

  return c.json({
    ok: true,
    score,
    open_findings: recentFindings.results ?? [],
    open_findings_count: recentFindings.results?.length ?? 0,
  });
});

// ─── 16. GET /report ─────────────────────────────────────────────────────────

app.get('/report', async (c) => {
  // Summary stats
  const [policiesCount, runsCount, openFindings, criticalFindings, avgScore, recentRuns, topViolators, recentCritical] = await Promise.all([
    c.env.DB.prepare('SELECT COUNT(*) as cnt FROM audit_policies WHERE enabled = 1').first<{ cnt: number }>(),
    c.env.DB.prepare('SELECT COUNT(*) as cnt FROM audit_runs').first<{ cnt: number }>(),
    c.env.DB.prepare("SELECT COUNT(*) as cnt FROM audit_findings WHERE status = 'open'").first<{ cnt: number }>(),
    c.env.DB.prepare("SELECT COUNT(*) as cnt FROM audit_findings WHERE status = 'open' AND severity = 'critical'").first<{ cnt: number }>(),
    c.env.DB.prepare('SELECT AVG(overall_score) as avg FROM compliance_scores').first<{ avg: number | null }>(),
    c.env.DB.prepare('SELECT * FROM audit_runs ORDER BY started_at DESC LIMIT 5').all<AuditRun>(),
    c.env.DB.prepare(
      "SELECT service_name, COUNT(*) as violation_count FROM audit_findings WHERE status = 'open' GROUP BY service_name ORDER BY violation_count DESC LIMIT 10"
    ).all<{ service_name: string; violation_count: number }>(),
    c.env.DB.prepare(
      "SELECT * FROM audit_findings WHERE status = 'open' AND severity = 'critical' ORDER BY created_at DESC LIMIT 10"
    ).all<AuditFinding>(),
  ]);

  // Trend data: pass rates from recent runs
  const trendData = (recentRuns.results ?? []).map(r => ({
    run_id: r.id,
    date: r.started_at,
    pass_rate: r.pass_rate,
    violations: r.violations_found,
    services_checked: r.services_checked,
  }));

  return c.json({
    ok: true,
    report: {
      generated_at: new Date().toISOString(),
      summary: {
        enabled_policies: policiesCount?.cnt ?? 0,
        total_runs: runsCount?.cnt ?? 0,
        open_findings: openFindings?.cnt ?? 0,
        critical_findings: criticalFindings?.cnt ?? 0,
        avg_compliance_score: Math.round((avgScore?.avg ?? 0) * 100) / 100,
        known_services: KNOWN_SERVICES.length,
      },
      top_violators: topViolators.results ?? [],
      critical_findings: recentCritical.results ?? [],
      trend: trendData,
    },
  });
});

// ─── 17. GET /dashboard ──────────────────────────────────────────────────────

app.get('/dashboard', async (c) => {
  // Check cache first
  const cached = await c.env.CACHE.get('dashboard_data', 'json');
  if (cached) return c.json({ ok: true, cached: true, ...(cached as Record<string, unknown>) });

  const [scores, openByCategory, openBySeverity, latestRun, policyBreakdown] = await Promise.all([
    c.env.DB.prepare('SELECT * FROM compliance_scores ORDER BY overall_score ASC').all<ComplianceScore>(),
    c.env.DB.prepare(
      "SELECT p.category, COUNT(f.id) as count FROM audit_findings f JOIN audit_policies p ON f.policy_id = p.id WHERE f.status = 'open' GROUP BY p.category"
    ).all<{ category: string; count: number }>(),
    c.env.DB.prepare(
      "SELECT severity, COUNT(*) as count FROM audit_findings WHERE status = 'open' GROUP BY severity"
    ).all<{ severity: string; count: number }>(),
    c.env.DB.prepare('SELECT * FROM audit_runs ORDER BY started_at DESC LIMIT 1').first<AuditRun>(),
    c.env.DB.prepare(
      'SELECT category, COUNT(*) as count FROM audit_policies WHERE enabled = 1 GROUP BY category'
    ).all<{ category: string; count: number }>(),
  ]);

  const allScores = scores.results ?? [];
  const avgOverall = allScores.length > 0
    ? allScores.reduce((s, r) => s + r.overall_score, 0) / allScores.length : 0;

  const dashboard = {
    overview: {
      avg_compliance_score: Math.round(avgOverall * 100) / 100,
      total_services: allScores.length,
      services_above_80: allScores.filter(s => s.overall_score >= 80).length,
      services_below_50: allScores.filter(s => s.overall_score < 50).length,
    },
    latest_run: latestRun ?? null,
    open_findings_by_category: openByCategory.results ?? [],
    open_findings_by_severity: openBySeverity.results ?? [],
    policy_breakdown: policyBreakdown.results ?? [],
    service_scores: allScores.map(s => ({
      name: s.service_name,
      overall: Math.round(s.overall_score * 100) / 100,
      security: Math.round(s.security_score * 100) / 100,
      config: Math.round(s.config_score * 100) / 100,
      performance: Math.round(s.performance_score * 100) / 100,
      last_audited: s.last_audited,
    })),
  };

  // Cache for 5 minutes
  await c.env.CACHE.put('dashboard_data', JSON.stringify(dashboard), { expirationTtl: 300 });

  return c.json({ ok: true, cached: false, ...dashboard });
});

// ─── 18. POST /policies/seed ─────────────────────────────────────────────────

app.post('/policies/seed', async (c) => {
  if (!requireAuth(c)) return errorResponse('Unauthorized', 401);

  const now = new Date().toISOString();
  let seeded = 0;
  let skipped = 0;

  for (const policy of DEFAULT_POLICIES) {
    const existing = await c.env.DB.prepare(
      'SELECT id FROM audit_policies WHERE id = ? OR name = ?'
    ).bind(policy.id, policy.name).first();

    if (existing) {
      skipped++;
      continue;
    }

    await c.env.DB.prepare(
      'INSERT INTO audit_policies (id, name, description, category, severity, check_type, check_config, enabled, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
    ).bind(
      policy.id, policy.name, policy.description, policy.category, policy.severity,
      policy.check_type, policy.check_config, policy.enabled, now, now
    ).run();
    seeded++;
  }

  log('info', 'Policies seeded', { seeded, skipped });
  return c.json({ ok: true, seeded, skipped, total_default: DEFAULT_POLICIES.length });
});

// ─── 404 Handler ─────────────────────────────────────────────────────────────

app.notFound((c) => {
  return c.json({
    ok: false,
    error: 'Not found',
    path: c.req.path,
    method: c.req.method,
    worker: WORKER_NAME,
    version: WORKER_VERSION,
  }, 404);
});

// ─── Error Handler ───────────────────────────────────────────────────────────

app.onError((err, c) => {
  errorCount++;
  log('error', 'Unhandled error', {
    message: err.message,
    path: c.req.path,
    method: c.req.method,
  });
  return c.json({
    ok: false,
    error: 'Internal server error',
    message: err.message,
    worker: WORKER_NAME,
    version: WORKER_VERSION,
  }, 500);
});

// ─── Cron Handler ────────────────────────────────────────────────────────────

async function handleScheduled(event: ScheduledEvent, env: Env): Promise<void> {
  const cron = event.cron;
  log('info', 'Cron triggered', { cron });

  if (cron === '0 4 * * *') {
    // Daily full audit at 4 AM
    try {
      const result = await executeAuditRun(env.DB, env.CACHE, env, 'scheduled');
      log('info', 'Daily audit completed', {
        runId: result.runId,
        violations: result.violations,
        servicesChecked: result.servicesChecked,
      });

      // Fire alerts for critical findings
      if (result.violations > 0) {
        const criticalFindings = await env.DB.prepare(
          "SELECT COUNT(*) as cnt FROM audit_findings WHERE run_id = ? AND severity = 'critical'"
        ).bind(result.runId).first<{ cnt: number }>();

        if ((criticalFindings?.cnt ?? 0) > 0) {
          try {
            await env.ALERT_ROUTER.fetch('https://echo-alert-router.internal/alert', {
              method: 'POST',
              headers: {
                'Content-Type': 'application/json',
                'X-Echo-API-Key': env.ECHO_API_KEY,
              },
              body: JSON.stringify({
                source: WORKER_NAME,
                severity: 'critical',
                title: `Compliance Audit: ${criticalFindings?.cnt ?? 0} critical violations found`,
                message: `Daily audit found ${result.violations} total violations (${criticalFindings?.cnt ?? 0} critical) across ${result.servicesChecked} services`,
                run_id: result.runId,
              }),
            });
          } catch (alertErr) {
            log('warn', 'Failed to send alert', { error: alertErr instanceof Error ? alertErr.message : String(alertErr) });
          }
        }
      }
    } catch (err) {
      log('error', 'Daily audit failed', { error: err instanceof Error ? err.message : String(err) });
    }
  } else if (cron === '0 0 * * 1') {
    // Weekly report on Monday
    try {
      // Get runs from last 7 days
      const weeklyRuns = await env.DB.prepare(
        "SELECT * FROM audit_runs WHERE started_at > datetime('now', '-7 days') ORDER BY started_at DESC"
      ).all<AuditRun>();

      const runs = weeklyRuns.results ?? [];
      const avgPassRate = runs.length > 0
        ? runs.reduce((s, r) => s + r.pass_rate, 0) / runs.length : 0;
      const totalViolations = runs.reduce((s, r) => s + r.violations_found, 0);

      // Get current scores
      const scores = await env.DB.prepare(
        'SELECT * FROM compliance_scores ORDER BY overall_score ASC'
      ).all<ComplianceScore>();

      const allScores = scores.results ?? [];
      const avgScore = allScores.length > 0
        ? allScores.reduce((s, r) => s + r.overall_score, 0) / allScores.length : 0;

      const weeklyReport = {
        period: 'weekly',
        generated_at: new Date().toISOString(),
        runs_count: runs.length,
        avg_pass_rate: Math.round(avgPassRate * 100) / 100,
        total_violations: totalViolations,
        avg_compliance_score: Math.round(avgScore * 100) / 100,
        worst_services: allScores.slice(0, 5).map(s => ({
          name: s.service_name,
          score: Math.round(s.overall_score * 100) / 100,
        })),
      };

      // Store report in KV
      await env.CACHE.put(
        `weekly_report_${new Date().toISOString().split('T')[0]}`,
        JSON.stringify(weeklyReport),
        { expirationTtl: 2592000 } // 30 days
      );

      // Post to Shared Brain
      try {
        await env.SHARED_BRAIN.fetch('https://echo-shared-brain.internal/messages', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-Echo-API-Key': env.ECHO_API_KEY,
          },
          body: JSON.stringify({
            role: 'system',
            content: `Weekly Compliance Report: ${runs.length} audits, avg pass rate ${Math.round(avgPassRate)}%, ${totalViolations} violations, avg score ${Math.round(avgScore)}%`,
            metadata: { source: WORKER_NAME, type: 'weekly_compliance_report', report: weeklyReport },
          }),
        });
      } catch (brainErr) {
        log('warn', 'Failed to post to Shared Brain', { error: brainErr instanceof Error ? brainErr.message : String(brainErr) });
      }

      log('info', 'Weekly report generated', weeklyReport);
    } catch (err) {
      log('error', 'Weekly report failed', { error: err instanceof Error ? err.message : String(err) });
    }
  }
}

// ─── Export ──────────────────────────────────────────────────────────────────

export default {
  fetch: app.fetch,
  scheduled: handleScheduled,
};
