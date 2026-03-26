-- Echo Compliance Auditor D1 Schema
-- Created: 2026-03-20

DROP TABLE IF EXISTS audit_waivers;
DROP TABLE IF EXISTS audit_findings;
DROP TABLE IF EXISTS compliance_scores;
DROP TABLE IF EXISTS audit_runs;
DROP TABLE IF EXISTS audit_policies;

CREATE TABLE audit_policies (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  description TEXT NOT NULL,
  category TEXT NOT NULL CHECK(category IN ('security', 'config', 'performance', 'naming', 'logging')),
  severity TEXT NOT NULL CHECK(severity IN ('critical', 'high', 'medium', 'low')),
  check_type TEXT NOT NULL,
  check_config TEXT NOT NULL DEFAULT '{}',
  enabled INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE audit_runs (
  id TEXT PRIMARY KEY,
  run_type TEXT NOT NULL CHECK(run_type IN ('scheduled', 'manual', 'targeted')),
  status TEXT NOT NULL CHECK(status IN ('running', 'completed', 'failed')) DEFAULT 'running',
  started_at TEXT NOT NULL DEFAULT (datetime('now')),
  completed_at TEXT,
  services_checked INTEGER NOT NULL DEFAULT 0,
  policies_checked INTEGER NOT NULL DEFAULT 0,
  violations_found INTEGER NOT NULL DEFAULT 0,
  pass_rate REAL NOT NULL DEFAULT 0.0
);

CREATE TABLE audit_findings (
  id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL,
  policy_id TEXT NOT NULL,
  service_name TEXT NOT NULL,
  finding_type TEXT NOT NULL CHECK(finding_type IN ('violation', 'warning', 'info')),
  severity TEXT NOT NULL CHECK(severity IN ('critical', 'high', 'medium', 'low')),
  description TEXT NOT NULL,
  evidence TEXT,
  remediation TEXT,
  status TEXT NOT NULL CHECK(status IN ('open', 'acknowledged', 'resolved', 'waived')) DEFAULT 'open',
  resolved_at TEXT,
  resolved_by TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (run_id) REFERENCES audit_runs(id),
  FOREIGN KEY (policy_id) REFERENCES audit_policies(id)
);

CREATE TABLE compliance_scores (
  id TEXT PRIMARY KEY,
  service_name TEXT NOT NULL UNIQUE,
  overall_score REAL NOT NULL DEFAULT 0.0,
  security_score REAL NOT NULL DEFAULT 0.0,
  config_score REAL NOT NULL DEFAULT 0.0,
  performance_score REAL NOT NULL DEFAULT 0.0,
  last_audited TEXT,
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE audit_waivers (
  id TEXT PRIMARY KEY,
  finding_id TEXT,
  policy_id TEXT NOT NULL,
  service_name TEXT NOT NULL,
  reason TEXT NOT NULL,
  waived_by TEXT NOT NULL,
  expires_at TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (finding_id) REFERENCES audit_findings(id),
  FOREIGN KEY (policy_id) REFERENCES audit_policies(id)
);

-- Indexes for query performance
CREATE INDEX idx_findings_run_id ON audit_findings(run_id);
CREATE INDEX idx_findings_policy_id ON audit_findings(policy_id);
CREATE INDEX idx_findings_service ON audit_findings(service_name);
CREATE INDEX idx_findings_status ON audit_findings(status);
CREATE INDEX idx_findings_severity ON audit_findings(severity);
CREATE INDEX idx_scores_service ON compliance_scores(service_name);
CREATE INDEX idx_runs_status ON audit_runs(status);
CREATE INDEX idx_runs_type ON audit_runs(run_type);
CREATE INDEX idx_policies_category ON audit_policies(category);
CREATE INDEX idx_policies_enabled ON audit_policies(enabled);
CREATE INDEX idx_waivers_service ON audit_waivers(service_name);
CREATE INDEX idx_waivers_policy ON audit_waivers(policy_id);
