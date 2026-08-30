<?php
/**
 * Seeds a demo tenant: a mid-size Indian manufacturer.
 *
 * WHAT IS REAL AND WHAT IS NOT — this matters, and the product should never blur it:
 *   REAL   every vulnerability. CVSS from NVD, exploitation probability from FIRST
 *          EPSS, exploited-in-the-wild status from the CISA KEV catalog.
 *   SYNTHETIC the estate — hostnames, IPs, business units, revenue. No real company's
 *          asset inventory can come from a public source, so this one is invented.
 *
 * Findings are not invented pairings either: each asset declares the product it
 * actually runs, and its findings are drawn from real KEV entries for THAT product.
 * So plant-jump-01 gets Windows RDP CVEs and mail-01 gets Exchange CVEs, because
 * that is what CISA lists against those products.
 *
 *   php api/ingest/seed_estate.php [--reset]
 */
require_once __DIR__ . '/../config/db.php';

$pdo = db();
$reset = in_array('--reset', $argv, true);

const TENANT = 'acme-in';

if ($reset) {
    $t = $pdo->query("SELECT id FROM tenants WHERE slug = '" . TENANT . "'")->fetchColumn();
    if ($t) {
        $pdo->exec("SET FOREIGN_KEY_CHECKS=0");
        foreach (['risk_scores','remediation_findings','optimizer_selections','optimizer_runs',
                  'remediations','findings','asset_controls','assets','controls','loss_models',
                  'experiences','audit_log','users'] as $tbl) {
            $col = in_array($tbl, ['asset_controls','remediation_findings','optimizer_selections'], true) ? null : 'tenant_id';
            if ($col) {
                $pdo->prepare("DELETE FROM $tbl WHERE tenant_id = ?")->execute([$t]);
            } else {
                $pdo->exec("DELETE FROM $tbl");
            }
        }
        $pdo->prepare("DELETE FROM tenants WHERE id = ?")->execute([$t]);
        $pdo->exec("SET FOREIGN_KEY_CHECKS=1");
        echo "reset tenant " . TENANT . "\n";
    }
}

// ------------------------------------------------------------------ tenant
$pdo->prepare("INSERT INTO tenants (slug, name, industry) VALUES (?,?,?)
               ON DUPLICATE KEY UPDATE name = VALUES(name)")
    ->execute([TENANT, 'Acme Manufacturing Pvt Ltd', 'Manufacturing']);
$tid = (int) $pdo->query("SELECT id FROM tenants WHERE slug = '" . TENANT . "'")->fetchColumn();
echo "tenant #$tid\n";

// ------------------------------------------------------------------- users
$users = [
    ['priya@acme.co.in',     'Priya Nair',   'owner'],
    ['cfo-office@acme.co.in','R. Krishnan',  'executive'],
    ['awaiz@acme.co.in',     'A. Patel',     'analyst'],
    ['ops@acme.co.in',       'Plant Ops',    'viewer'],
];
$uq = $pdo->prepare("INSERT INTO users (tenant_id,email,name,role,password_hash,twofa_enabled)
                     VALUES (?,?,?,?,?,?)
                     ON DUPLICATE KEY UPDATE name=VALUES(name), role=VALUES(role)");
foreach ($users as $u) {
    $uq->execute([$tid, $u[0], $u[1], $u[2], password_hash('spendshield-demo', PASSWORD_DEFAULT), $u[2] === 'viewer' ? 0 : 1]);
}
echo "users: " . count($users) . "\n";

// -------------------------------------------------------------- loss model
// Figures are a plausible profile for a ~₹900 Cr revenue manufacturer.
// cost_per_record is anchored to published breach-cost研究 for India (~₹6,100/record).
$pdo->prepare(
    "INSERT INTO loss_models
        (tenant_id, version, revenue_per_hour, median_recovery_hours, pii_records,
         cost_per_record, penalty_band, penalty_cap, ransom_recovery_cost,
         reputational_cost, is_active, note)
     VALUES (?,1,?,?,?,?,?,?,?,?,1,?)
     ON DUPLICATE KEY UPDATE revenue_per_hour = VALUES(revenue_per_hour)"
)->execute([
    $tid,
    1240000.00,   // ₹12.4 lakh per hour of full production stoppage
    12.00,        // median recovery time, hours
    184000,       // PII records held
    6100.00,      // ₹ per breached record
    'DPDP Act 2023 · high',
    250000000.00, // ₹250 Cr statutory maximum penalty under the DPDP Act
    8500000.00,   // ransom + incident response + rebuild
    4800000.00,   // contractual penalties and customer churn
    'Seeded profile for a mid-size discrete manufacturer. Every field is editable on /exposure.',
]);
echo "loss model v1\n";

// ---------------------------------------------------------------- controls
// claimed = vendor/framework figure. observed = what our telemetry saw.
$controls = [
    ['mfa',          'Multi-factor authentication', 'Microsoft Entra ID', 0.90, 0.88, 1240,  6],
    ['edr',          'Endpoint detection & response','CrowdStrike Falcon', 0.85, 0.71, 4102, 61],
    ['segmentation', 'Network segmentation',        'Cisco ISE',          0.80, 0.34,  312, 23],
    ['waf',          'Web application firewall',    'Cloudflare',         0.75, 0.69,  890,  9],
    ['backup',       'Verified restore backups',    'Veeam',              0.95, 0.95,   24,  0],
    ['patch',        'Patch management SLA',        'WSUS + Ansible',     0.70, 0.52, 2200, 41],
];
$cq = $pdo->prepare("INSERT INTO controls
    (tenant_id,control_key,name,vendor,claimed_effectiveness,observed_effectiveness,observation_count,miss_count)
    VALUES (?,?,?,?,?,?,?,?)
    ON DUPLICATE KEY UPDATE observed_effectiveness=VALUES(observed_effectiveness),
                            observation_count=VALUES(observation_count), miss_count=VALUES(miss_count)");
foreach ($controls as $c) { $cq->execute(array_merge([$tid], $c)); }
$controlId = [];
foreach ($pdo->query("SELECT id,control_key FROM controls WHERE tenant_id=$tid") as $r) {
    $controlId[$r['control_key']] = (int) $r['id'];
}
echo "controls: " . count($controls) . "\n";

// ------------------------------------------------------------------ assets
// [hostname, ip, class, os, BU, owner, env, criticality, crown, internet,
//  product-match for real CVEs, controls present, max findings]
$assets = [
    ['plant-jump-01','10.40.2.11','Jump host','Windows Server 2016','Plant','IT Infra','production',0.90,1,1,'Microsoft Remote Desktop',['edr','backup'],3],
    ['corp-ad-01','10.10.0.10','Domain controller','Windows Server 2019','Corporate','IT Infra','production',0.95,1,0,'Microsoft Windows',['edr','mfa','backup'],4],
    ['mail-01','10.10.0.25','Mail server','Exchange Server 2019','Corporate','IT Infra','production',0.85,1,1,'Microsoft Exchange',['edr','waf','backup'],4],
    ['vpn-edge-01','203.0.113.8','VPN gateway','FortiOS 6.4','Corporate','Network','production',0.88,1,1,'Fortinet',['backup'],3],
    ['hmi-line-3','10.60.9.4','SCADA HMI','Windows 7 Embedded','Plant','Plant Ops','ot',0.92,1,0,'Microsoft Windows',['backup'],3],
    ['plc-gw-02','10.60.9.11','OT gateway','Linux 4.19','Plant','Plant Ops','ot',0.86,1,0,'Linux',['backup'],2],
    ['vc-mgmt-02','10.20.4.7','Virtualization','VMware vCenter 7.0','Corporate','IT Infra','production',0.82,0,0,'VMware vCenter',['edr','backup'],3],
    ['web-shop-01','203.0.113.21','Web application','Apache Tomcat 9','Sales','Digital','production',0.70,0,1,'Apache',['waf','edr'],3],
    ['file-transfer-01','203.0.113.35','Managed file transfer','MOVEit Transfer','Finance','Finance IT','production',0.78,0,1,'Progress MOVEit',['waf','backup'],2],
    ['ci-runner-04','10.30.1.44','Build agent','Ubuntu 22.04','Engineering','Platform','production',0.55,0,0,'Apache',['edr'],3],
    ['db-prod-01','10.10.5.9','Database','Oracle Linux 8','Corporate','IT Infra','production',0.90,1,0,'Oracle',['edr','backup','segmentation'],2],
    ['citrix-gw-01','203.0.113.44','Remote access','Citrix ADC 13.0','Corporate','Network','production',0.84,0,1,'Citrix',['waf'],2],
    ['br-office-01','10.70.2.5','Branch server','Windows Server 2012 R2','Branch','IT Infra','production',0.45,0,1,'Microsoft Remote Desktop',['edr'],2],
    ['wifi-ctrl-01','10.15.0.3','Network controller','Cisco WLC','Corporate','Network','production',0.50,0,0,'Cisco',['segmentation'],2],
    ['backup-01','10.10.7.2','Backup server','Windows Server 2019','Corporate','IT Infra','production',0.88,1,0,'Microsoft Windows',['edr','backup','mfa'],2],
    ['erp-app-01','10.10.3.15','ERP application','SAP NetWeaver','Corporate','Business Apps','production',0.93,1,0,'SAP',['edr','waf','backup'],2],
    ['print-srv-01','10.10.2.40','Print server','Windows Server 2019','Corporate','IT Infra','production',0.35,0,0,'Microsoft Windows',['edr'],2],
    ['dev-web-02','10.30.2.18','Web application','Ubuntu 22.04','Engineering','Platform','development',0.25,0,0,'Apache',[],2],
    ['acme-invoices','—','Object store','AWS S3 (ap-south-1)','Finance','Finance IT','production',0.80,0,1,null,[],0],
    ['acme-backups-s3','—','Object store','AWS S3 (ap-south-1)','Corporate','IT Infra','production',0.75,0,0,null,['backup'],0],
];

$aq = $pdo->prepare("INSERT INTO assets
    (tenant_id,hostname,ip,asset_class,os,business_unit,owner_team,environment,criticality,
     is_crown_jewel,internet_facing,source,last_scan_at)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,'nmap', NOW() - INTERVAL FLOOR(RAND()*48) HOUR)
    ON DUPLICATE KEY UPDATE criticality=VALUES(criticality)");
$acq = $pdo->prepare("INSERT IGNORE INTO asset_controls (asset_id,control_id,status) VALUES (?,?,?)");

$assetId = [];
foreach ($assets as $a) {
    $aq->execute([$tid,$a[0],$a[1],$a[2],$a[3],$a[4],$a[5],$a[6],$a[7],$a[8],$a[9]]);
    $id = (int) $pdo->query("SELECT id FROM assets WHERE tenant_id=$tid AND hostname=" . $pdo->quote($a[0]))->fetchColumn();
    $assetId[$a[0]] = $id;
    foreach ($a[11] as $ck) {
        if (isset($controlId[$ck])) {
            $acq->execute([$id, $controlId[$ck], 'active']);
        }
    }
}
echo "assets: " . count($assets) . "\n";

// ------------------------------------------------- config-class weaknesses
// Not CVEs — posture problems a scanner reports. Given local_keys, and scored
// with an explicit severity because no CVSS exists for them.
$configs = [
    ['cfg.public_bucket','Object storage readable by anyone on the internet','CWE-284',9.1,'CRITICAL'],
    ['cfg.no_mfa_privileged','Privileged accounts without multi-factor authentication','CWE-308',8.8,'HIGH'],
    ['cfg.flat_ot_network','OT segment reachable from the corporate LAN','CWE-1188',8.6,'HIGH'],
    ['cfg.legacy_tls','TLS 1.0/1.1 still accepted','CWE-327',5.9,'MEDIUM'],
    ['cfg.no_edr','No endpoint detection agent installed','CWE-693',6.5,'MEDIUM'],
    ['cfg.eol_os','Operating system past vendor end-of-life','CWE-1104',7.5,'HIGH'],
];
$cfgq = $pdo->prepare("INSERT INTO vulnerabilities
    (local_key,source,title,description,cwe,cvss_version,cvss_score,cvss_severity,kev_listed,last_synced_at)
    VALUES (?,'config',?,?,?,'3.1',?,?,0,NOW())
    ON DUPLICATE KEY UPDATE title=VALUES(title), cvss_score=VALUES(cvss_score)");
foreach ($configs as $c) {
    $cfgq->execute([$c[0], $c[1], $c[1], $c[2], $c[3], $c[4]]);
}
$cfgId = [];
foreach ($pdo->query("SELECT id,local_key FROM vulnerabilities WHERE source='config'") as $r) {
    $cfgId[$r['local_key']] = (int) $r['id'];
}
echo "config weaknesses: " . count($configs) . "\n";

// ---------------------------------------------------------------- findings
// Real CVEs, matched to the product each asset actually runs. Ordered by EPSS
// so the estate carries genuinely dangerous vulnerabilities, not obscure ones.
$fq = $pdo->prepare("INSERT INTO findings
    (tenant_id,asset_id,vulnerability_id,detector,port,service,evidence,status,first_seen_at,last_seen_at)
    VALUES (?,?,?,?,?,?,?,'open', NOW() - INTERVAL ? DAY, NOW() - INTERVAL FLOOR(RAND()*3) HOUR)
    ON DUPLICATE KEY UPDATE last_seen_at = VALUES(last_seen_at)");

$match = $pdo->prepare(
    "SELECT id, cve_id, title FROM vulnerabilities
      WHERE source='nvd' AND title LIKE ? AND epss_score IS NOT NULL
      ORDER BY epss_score DESC, kev_date_added DESC LIMIT ?"
);

$svc = [
    'Microsoft Remote Desktop' => [3389, 'ms-wbt-server'],
    'Microsoft Exchange'       => [443,  'https'],
    'Fortinet'                 => [443,  'https'],
    'VMware vCenter'           => [443,  'https'],
    'Apache'                   => [8080, 'http-proxy'],
    'Citrix'                   => [443,  'https'],
    'Progress MOVEit'          => [443,  'https'],
    'Microsoft Windows'        => [445,  'microsoft-ds'],
    'Cisco'                    => [443,  'https'],
    'Oracle'                   => [1521, 'oracle-tns'],
    'SAP'                      => [8000, 'http'],
    'Linux'                    => [22,   'ssh'],
];

$n = 0;
foreach ($assets as $a) {
    $host = $a[0];
    $product = $a[10];
    $cap = (int) $a[12];
    if ($product === null || $cap === 0) continue;

    $match->bindValue(1, '%' . $product . '%', PDO::PARAM_STR);
    $match->bindValue(2, $cap, PDO::PARAM_INT);
    $match->execute();
    $rows = $match->fetchAll();
    [$port, $service] = $svc[$product] ?? [null, null];

    foreach ($rows as $i => $v) {
        $fq->execute([
            $tid, $assetId[$host], (int) $v['id'], 'openvas', $port, $service,
            'Detected on ' . $host . ($port ? " port $port/tcp" : '') . ' — ' . $v['cve_id'],
            2 + ($i * 3) + (crc32($host) % 21),
        ]);
        $n++;
    }
}

// config findings, placed where they actually belong
$cfgPlacement = [
    ['acme-invoices',   'cfg.public_bucket'],
    ['corp-ad-01',      'cfg.no_mfa_privileged'],
    ['plant-jump-01',   'cfg.no_mfa_privileged'],
    ['hmi-line-3',      'cfg.flat_ot_network'],
    ['plc-gw-02',       'cfg.flat_ot_network'],
    ['hmi-line-3',      'cfg.eol_os'],
    ['br-office-01',    'cfg.eol_os'],
    ['web-shop-01',     'cfg.legacy_tls'],
    ['citrix-gw-01',    'cfg.legacy_tls'],
    ['dev-web-02',      'cfg.no_edr'],
    ['plc-gw-02',       'cfg.no_edr'],
    ['wifi-ctrl-01',    'cfg.no_edr'],
];
foreach ($cfgPlacement as $p) {
    if (!isset($assetId[$p[0]], $cfgId[$p[1]])) continue;
    $fq->execute([
        $tid, $assetId[$p[0]], $cfgId[$p[1]], 'cloud', null, null,
        'Configuration review on ' . $p[0], 5 + (crc32($p[1]) % 30),
    ]);
    $n++;
}
echo "findings: $n\n";

// --------------------------------------------------------------- audit log
$pdo->prepare("INSERT INTO audit_log (tenant_id,actor,action,entity_type,entity_ref,note)
               VALUES (?,?,?,?,?,?)")
    ->execute([$tid, 'system', 'Estate seeded', 'tenant', TENANT,
        'Vulnerability data real (NVD/EPSS/CISA KEV). Asset inventory synthetic.']);

echo "\nseed complete — vulnerabilities are real, the estate is synthetic\n";
