-- SpendShield — schema (Phase 1)
-- MariaDB 10.4+ / MySQL 8. All money is INR, DECIMAL(18,2).
-- Money never lives in a float. Risk factors are DECIMAL(6,4) in [0,1].

SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

-- ---------------------------------------------------------------- tenancy
CREATE TABLE IF NOT EXISTS tenants (
  id          INT AUTO_INCREMENT PRIMARY KEY,
  slug        VARCHAR(64)  NOT NULL UNIQUE,
  name        VARCHAR(160) NOT NULL,
  industry    VARCHAR(80)  NULL,
  created_at  TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS users (
  id             INT AUTO_INCREMENT PRIMARY KEY,
  tenant_id      INT NOT NULL,
  email          VARCHAR(190) NOT NULL UNIQUE,
  name           VARCHAR(120) NOT NULL,
  role           ENUM('owner','executive','analyst','viewer') NOT NULL DEFAULT 'viewer',
  password_hash  VARCHAR(255) NULL,
  twofa_enabled  TINYINT(1)   NOT NULL DEFAULT 0,
  scope_json     TEXT         NULL,          -- asset groups this user may see; NULL = all
  last_active_at TIMESTAMP    NULL,
  created_at     TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
  deleted_at     TIMESTAMP    NULL,
  KEY idx_users_tenant (tenant_id),
  CONSTRAINT fk_users_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ---------------------------------------------------------------- estate
CREATE TABLE IF NOT EXISTS assets (
  id               INT AUTO_INCREMENT PRIMARY KEY,
  tenant_id        INT NOT NULL,
  hostname         VARCHAR(160) NOT NULL,
  ip               VARCHAR(45)  NULL,
  asset_class      VARCHAR(60)  NOT NULL,     -- jump host, mail, scada hmi, object store...
  os               VARCHAR(120) NULL,
  business_unit    VARCHAR(80)  NULL,
  owner_team       VARCHAR(80)  NULL,
  environment      ENUM('production','staging','development','ot') NOT NULL DEFAULT 'production',
  -- criticality is the C in the risk formula: how much this system matters. 0..1
  criticality      DECIMAL(6,4) NOT NULL DEFAULT 0.5000,
  is_crown_jewel   TINYINT(1)   NOT NULL DEFAULT 0,
  internet_facing  TINYINT(1)   NOT NULL DEFAULT 0,
  -- what a full outage of THIS asset costs per hour, when it differs from the tenant default
  revenue_per_hour DECIMAL(18,2) NULL,
  pii_records      INT          NULL,
  source           VARCHAR(40)  NOT NULL DEFAULT 'manual',   -- nmap | cmdb | manual | aws
  last_scan_at     TIMESTAMP    NULL,
  decommissioned_at TIMESTAMP   NULL,
  created_at       TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uq_asset (tenant_id, hostname),
  KEY idx_assets_tenant (tenant_id),
  CONSTRAINT fk_assets_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS controls (
  id                     INT AUTO_INCREMENT PRIMARY KEY,
  tenant_id              INT NOT NULL,
  control_key            VARCHAR(60)  NOT NULL,     -- mfa | edr | segmentation | waf | backup
  name                   VARCHAR(160) NOT NULL,
  vendor                 VARCHAR(120) NULL,
  -- what the vendor/framework claims, and what our own telemetry observed. The
  -- score uses OBSERVED whenever we have enough events to have observed anything.
  claimed_effectiveness  DECIMAL(6,4) NOT NULL DEFAULT 0.5000,
  observed_effectiveness DECIMAL(6,4) NULL,
  observation_count      INT NOT NULL DEFAULT 0,
  miss_count             INT NOT NULL DEFAULT 0,
  created_at             TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uq_control (tenant_id, control_key),
  CONSTRAINT fk_controls_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS asset_controls (
  asset_id      INT NOT NULL,
  control_id    INT NOT NULL,
  status        ENUM('active','partial','absent') NOT NULL DEFAULT 'active',
  PRIMARY KEY (asset_id, control_id),
  CONSTRAINT fk_ac_asset   FOREIGN KEY (asset_id)   REFERENCES assets(id)   ON DELETE CASCADE,
  CONSTRAINT fk_ac_control FOREIGN KEY (control_id) REFERENCES controls(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ------------------------------------------------- vulnerability catalog
-- Tenant-independent. Synced from NVD (CVSS), FIRST EPSS, and CISA KEV.
CREATE TABLE IF NOT EXISTS vulnerabilities (
  id               INT AUTO_INCREMENT PRIMARY KEY,
  cve_id           VARCHAR(32)  NULL UNIQUE,   -- NULL for config/posture weaknesses
  local_key        VARCHAR(64)  NULL UNIQUE,   -- e.g. cfg.public_bucket
  source           ENUM('nvd','config') NOT NULL DEFAULT 'nvd',
  title            VARCHAR(255) NOT NULL,
  description      TEXT         NULL,
  cwe              VARCHAR(32)  NULL,
  cvss_version     VARCHAR(8)   NULL,
  cvss_score       DECIMAL(4,1) NULL,
  cvss_severity    VARCHAR(16)  NULL,
  cvss_vector      VARCHAR(120) NULL,
  epss_score       DECIMAL(9,8) NULL,          -- FIRST EPSS, probability of exploitation in 30d
  epss_percentile  DECIMAL(9,8) NULL,
  epss_asof        DATE         NULL,
  kev_listed       TINYINT(1)   NOT NULL DEFAULT 0,
  kev_date_added   DATE         NULL,
  kev_ransomware   TINYINT(1)   NOT NULL DEFAULT 0,
  -- which channels this weakness can actually hurt, from the real CVSS vector
  impact_c         TINYINT(1)   NOT NULL DEFAULT 0,
  impact_i         TINYINT(1)   NOT NULL DEFAULT 0,
  impact_a         TINYINT(1)   NOT NULL DEFAULT 0,
  published_at     DATETIME     NULL,
  last_synced_at   TIMESTAMP    NULL,
  KEY idx_vuln_kev (kev_listed),
  KEY idx_vuln_epss (epss_score)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ---------------------------------------------------------------- findings
CREATE TABLE IF NOT EXISTS findings (
  id                INT AUTO_INCREMENT PRIMARY KEY,
  tenant_id         INT NOT NULL,
  asset_id          INT NOT NULL,
  vulnerability_id  INT NOT NULL,
  detector          VARCHAR(40) NOT NULL DEFAULT 'openvas',   -- openvas | nmap | wazuh | cloud | manual
  port              INT NULL,
  service           VARCHAR(60) NULL,
  evidence          TEXT NULL,
  status            ENUM('open','accepted','remediated','closed') NOT NULL DEFAULT 'open',
  accepted_reason   VARCHAR(255) NULL,
  accepted_until    DATE NULL,
  accepted_by       INT NULL,
  first_seen_at     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_seen_at      TIMESTAMP NULL,
  closed_at         TIMESTAMP NULL,
  UNIQUE KEY uq_finding (asset_id, vulnerability_id, port),
  KEY idx_find_tenant_status (tenant_id, status),
  CONSTRAINT fk_find_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id),
  CONSTRAINT fk_find_asset  FOREIGN KEY (asset_id)  REFERENCES assets(id) ON DELETE CASCADE,
  CONSTRAINT fk_find_vuln   FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ------------------------------------------------------------- loss model
CREATE TABLE IF NOT EXISTS loss_models (
  id                    INT AUTO_INCREMENT PRIMARY KEY,
  tenant_id             INT NOT NULL,
  version               INT NOT NULL DEFAULT 1,
  revenue_per_hour      DECIMAL(18,2) NOT NULL,
  median_recovery_hours DECIMAL(6,2)  NOT NULL DEFAULT 12.00,
  pii_records           INT           NOT NULL DEFAULT 0,
  cost_per_record       DECIMAL(12,2) NOT NULL DEFAULT 0.00,   -- INR per breached record
  penalty_band          VARCHAR(60)   NULL,                    -- e.g. "DPDP Act · high"
  penalty_cap           DECIMAL(18,2) NOT NULL DEFAULT 0.00,
  ransom_recovery_cost  DECIMAL(18,2) NOT NULL DEFAULT 0.00,
  reputational_cost     DECIMAL(18,2) NOT NULL DEFAULT 0.00,
  is_active             TINYINT(1)    NOT NULL DEFAULT 1,
  note                  VARCHAR(255)  NULL,
  created_at            TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uq_loss_version (tenant_id, version),
  CONSTRAINT fk_loss_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ------------------------------------------------------------ risk scores
-- One row per (finding, computation). is_current marks the live one; the rest
-- are history, which is what makes the exposure trend chart real.
CREATE TABLE IF NOT EXISTS risk_scores (
  id                INT AUTO_INCREMENT PRIMARY KEY,
  finding_id        INT NOT NULL,
  tenant_id         INT NOT NULL,
  loss_model_version INT NOT NULL,
  -- the five factors, stored so the finding page can show its own arithmetic
  severity_factor   DECIMAL(6,4) NOT NULL,
  threat_probability DECIMAL(6,4) NOT NULL,
  asset_criticality DECIMAL(6,4) NOT NULL,
  exposure_factor   DECIMAL(6,4) NOT NULL,
  control_gap       DECIMAL(6,4) NOT NULL,
  raw_risk          DECIMAL(9,6) NOT NULL,
  -- money
  sle               DECIMAL(18,2) NOT NULL,   -- single loss expectancy
  ale_likely        DECIMAL(18,2) NOT NULL,   -- annualized loss expectancy
  ale_min           DECIMAL(18,2) NOT NULL,   -- P10
  ale_max           DECIMAL(18,2) NOT NULL,   -- P90
  confidence        DECIMAL(4,3) NOT NULL DEFAULT 0.500,
  agent_key         VARCHAR(80)  NULL,
  reuse_type        ENUM('fresh','exact','warehouse','knowledge') NOT NULL DEFAULT 'fresh',
  cost_usd          DECIMAL(10,6) NOT NULL DEFAULT 0,
  is_current        TINYINT(1)   NOT NULL DEFAULT 1,
  computed_at       TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
  KEY idx_rs_current (tenant_id, is_current),
  KEY idx_rs_finding (finding_id, is_current),
  CONSTRAINT fk_rs_finding FOREIGN KEY (finding_id) REFERENCES findings(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- --------------------------------------------------------- remediations
CREATE TABLE IF NOT EXISTS remediations (
  id                    INT AUTO_INCREMENT PRIMARY KEY,
  tenant_id             INT NOT NULL,
  name                  VARCHAR(190) NOT NULL,
  description           TEXT NULL,
  cost_inr              DECIMAL(18,2) NOT NULL,
  effort_days           INT NOT NULL DEFAULT 1,
  -- what it changes: either raises a control's effectiveness, or eliminates findings
  control_key           VARCHAR(60) NULL,
  effectiveness_target  DECIMAL(6,4) NULL,   -- control rises TO this value
  eliminates            TINYINT(1) NOT NULL DEFAULT 0,  -- 1 = the finding goes away entirely
  status                ENUM('proposed','approved','in_progress','done','failed') NOT NULL DEFAULT 'proposed',
  created_at            TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  KEY idx_rem_tenant (tenant_id),
  CONSTRAINT fk_rem_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS remediation_findings (
  remediation_id INT NOT NULL,
  finding_id     INT NOT NULL,
  PRIMARY KEY (remediation_id, finding_id),
  CONSTRAINT fk_rf_rem  FOREIGN KEY (remediation_id) REFERENCES remediations(id) ON DELETE CASCADE,
  CONSTRAINT fk_rf_find FOREIGN KEY (finding_id)     REFERENCES findings(id)     ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS optimizer_runs (
  id               INT AUTO_INCREMENT PRIMARY KEY,
  tenant_id        INT NOT NULL,
  budget_inr       DECIMAL(18,2) NOT NULL,
  allocated_inr    DECIMAL(18,2) NOT NULL DEFAULT 0,
  exposure_before  DECIMAL(18,2) NOT NULL DEFAULT 0,
  exposure_removed DECIMAL(18,2) NOT NULL DEFAULT 0,
  solved_ms        INT NOT NULL DEFAULT 0,
  constraints_json TEXT NULL,
  created_by       INT NULL,
  created_at       TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  KEY idx_or_tenant (tenant_id),
  CONSTRAINT fk_or_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS optimizer_selections (
  run_id           INT NOT NULL,
  remediation_id   INT NOT NULL,
  selected         TINYINT(1) NOT NULL DEFAULT 0,
  cost_inr         DECIMAL(18,2) NOT NULL,
  exposure_removed DECIMAL(18,2) NOT NULL,
  ratio            DECIMAL(12,4) NOT NULL,
  reason           VARCHAR(190) NULL,          -- why an unselected option lost
  PRIMARY KEY (run_id, remediation_id),
  CONSTRAINT fk_os_run FOREIGN KEY (run_id) REFERENCES optimizer_runs(id) ON DELETE CASCADE,
  CONSTRAINT fk_os_rem FOREIGN KEY (remediation_id) REFERENCES remediations(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- --------------------------------------------------------- agent registry
-- Mirrors the soundd.ai registry: an agent is a stored capability row.
CREATE TABLE IF NOT EXISTS agents (
  id             INT AUTO_INCREMENT PRIMARY KEY,
  agent_key      VARCHAR(80) NOT NULL UNIQUE,
  kind           ENUM('control','task') NOT NULL DEFAULT 'task',
  origin         ENUM('fixed','dynamic') NOT NULL DEFAULT 'fixed',
  name           VARCHAR(160) NOT NULL,
  description    TEXT NULL,
  category       VARCHAR(60) NULL,
  template       TEXT NULL,
  cand_template  TEXT NULL,
  cand_uses      INT NOT NULL DEFAULT 0,
  cand_quality   DECIMAL(4,2) NULL,
  axis_scores    TEXT NULL,
  model_tier     ENUM('cheap','standard','strong') NOT NULL DEFAULT 'standard',
  model_id       VARCHAR(120) NULL,
  cache_ttl      INT NOT NULL DEFAULT 1209600,
  retrieval_plan TEXT NULL,
  status         ENUM('canary','active','deprecated','retired') NOT NULL DEFAULT 'active',
  pinned         TINYINT(1) NOT NULL DEFAULT 0,
  merged_into    VARCHAR(80) NULL,
  version        INT NOT NULL DEFAULT 1,
  quality_score  DECIMAL(4,2) NULL,
  uses           INT NOT NULL DEFAULT 0,
  cache_hits     INT NOT NULL DEFAULT 0,
  cost_usd       DECIMAL(10,6) NOT NULL DEFAULT 0,
  created_by_user_id INT NULL,
  created_at     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS experiences (
  id           INT AUTO_INCREMENT PRIMARY KEY,
  tenant_id    INT NOT NULL,
  finding_id   INT NULL,
  agent_key    VARCHAR(80) NULL,
  reuse_type   VARCHAR(20) NOT NULL DEFAULT 'fresh',
  model        VARCHAR(120) NULL,
  quality      DECIMAL(4,2) NULL,
  latency_ms   INT NOT NULL DEFAULT 0,
  cost_usd     DECIMAL(10,6) NOT NULL DEFAULT 0,
  created_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  KEY idx_exp_tenant (tenant_id, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ------------------------------------------------------------- audit log
CREATE TABLE IF NOT EXISTS audit_log (
  id            INT AUTO_INCREMENT PRIMARY KEY,
  tenant_id     INT NOT NULL,
  actor         VARCHAR(160) NOT NULL DEFAULT 'system',
  action        VARCHAR(120) NOT NULL,
  entity_type   VARCHAR(60)  NULL,
  entity_ref    VARCHAR(120) NULL,
  before_value  VARCHAR(190) NULL,
  after_value   VARCHAR(190) NULL,
  money_effect  DECIMAL(18,2) NULL,   -- what this change moved, in INR
  note          VARCHAR(255) NULL,
  created_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  KEY idx_audit_tenant (tenant_id, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ------------------------------------------------- monitoring / feed health
CREATE TABLE IF NOT EXISTS feed_runs (
  id            INT AUTO_INCREMENT PRIMARY KEY,
  feed          VARCHAR(40) NOT NULL,     -- kev | epss | nvd
  status        ENUM('ok','failed','partial') NOT NULL,
  records       INT NOT NULL DEFAULT 0,
  changed       INT NOT NULL DEFAULT 0,
  message       VARCHAR(255) NULL,
  duration_ms   INT NOT NULL DEFAULT 0,
  ran_at        TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  KEY idx_feed (feed, ran_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

SET FOREIGN_KEY_CHECKS = 1;
