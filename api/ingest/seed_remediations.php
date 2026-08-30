<?php
/**
 * Seeds the remediation catalogue — the options the optimizer chooses between.
 *
 * Each option is linked to the REAL findings it would fix, resolved by querying
 * the estate rather than by hardcoding ids. Costs are realistic Indian
 * mid-market figures (licence + implementation + internal effort); they are the
 * one part a customer always replaces with their own quotes.
 *
 *   php api/ingest/seed_remediations.php [--reset]
 */
require_once __DIR__ . '/../config/db.php';

$pdo = db();
$tid = (int) $pdo->query("SELECT id FROM tenants WHERE slug = 'acme-in'")->fetchColumn();
if (!$tid) { fwrite(STDERR, "seed the estate first\n"); exit(1); }

if (in_array('--reset', $argv, true)) {
    $pdo->exec("DELETE FROM remediation_findings WHERE remediation_id IN
                (SELECT id FROM remediations WHERE tenant_id = $tid)");
    $pdo->exec("DELETE FROM remediations WHERE tenant_id = $tid");
    echo "cleared existing remediations\n";
}

/**
 * Each entry: name, cost, effort days, eliminates?, control_key, target,
 * and a WHERE clause selecting the findings it fixes.
 */
$catalog = [
    [
        'Close public object storage and enforce a block-public-access policy', 40000, 2, 1, null, null,
        "v.local_key = 'cfg.public_bucket'",
        'One bucket policy change plus a tenancy-wide guardrail. The cheapest line in the catalogue and the largest single exposure in the estate.',
    ],
    [
        'Disable TLS 1.0 and 1.1 on public endpoints', 30000, 1, 1, null, null,
        "v.local_key = 'cfg.legacy_tls'",
        'Configuration change on the edge, plus a compatibility check with two legacy partner integrations.',
    ],
    [
        'Patch Citrix ADC to the current maintenance release', 85000, 3, 1, null, null,
        "a.hostname = 'citrix-gw-01' AND v.cve_id IS NOT NULL",
        'Vendor firmware upgrade with a maintenance window. Closes two actively-exploited gateway CVEs.',
    ],
    [
        'Upgrade FortiOS on the VPN gateway', 95000, 2, 1, null, null,
        "a.hostname = 'vpn-edge-01' AND v.cve_id IS NOT NULL",
        'Firmware upgrade during a change window; removes the path-traversal class of findings.',
    ],
    [
        'Patch Exchange to the current cumulative update', 110000, 4, 1, null, null,
        "a.hostname = 'mail-01' AND v.cve_id IS NOT NULL",
        'ProxyLogon/ProxyShell family. Needs a weekend window and a mailbox database check afterwards.',
    ],
    [
        'Patch vCenter', 120000, 2, 1, null, null,
        "a.hostname = 'vc-mgmt-02' AND v.cve_id IS NOT NULL",
        'Straightforward appliance update; the management plane is the crown jewel behind the crown jewels.',
    ],
    [
        'Remediate Log4j across build and web tiers', 220000, 8, 1, null, null,
        "v.cve_id = 'CVE-2021-44228'",
        'Dependency upgrade plus a rebuild of three service images. Effort, not licence cost.',
    ],
    [
        'Patch Oracle WebLogic on the production database host', 150000, 3, 1, null, null,
        "a.hostname = 'db-prod-01' AND v.cve_id IS NOT NULL",
        'Quarterly Oracle CPU applied out of cycle.',
    ],
    [
        'Patch SAP NetWeaver to the current support stack', 180000, 5, 1, null, null,
        "a.hostname = 'erp-app-01' AND v.cve_id IS NOT NULL",
        'Support-stack update with a regression test cycle against finance postings.',
    ],
    [
        'Multi-factor authentication on all privileged access', 240000, 10, 1, 'mfa', 0.9000,
        "v.local_key = 'cfg.no_mfa_privileged'",
        'Conditional Access covering jump hosts, domain admins and the VPN. Licences plus rollout.',
    ],
    [
        'Segment the OT network from the corporate LAN', 960000, 25, 1, 'segmentation', 0.8000,
        "v.local_key = 'cfg.flat_ot_network'",
        'Firewall pair, VLAN redesign and a conduit policy for line 3. The expensive one, and the one the plant has been asking for.',
    ],
    [
        'Deploy endpoint detection to the remaining estate', 1400000, 20, 1, 'edr', 0.7100,
        "v.local_key = 'cfg.no_edr'",
        'Agent licences for the assets that have none, including the OT gateway where an agent is supportable.',
    ],
    [
        'Replace the end-of-life Windows 7 HMI', 1850000, 45, 1, null, null,
        "v.local_key = 'cfg.eol_os'",
        'Hardware plus vendor-supported HMI software. Long lead time; the only real fix for an unpatchable host.',
    ],
    [
        'Tune the web application firewall to blocking mode', 350000, 12, 0, 'waf', 0.8500,
        "a.hostname IN ('web-shop-01','file-transfer-01') AND v.cve_id IS NOT NULL",
        'Moves the WAF from detection to prevention on the two public applications, after a false-positive burn-in.',
    ],
    [
        'Cut the patch SLA from 30 days to 7', 1200000, 60, 0, 'patch', 0.8000,
        "v.cve_id IS NOT NULL AND a.internet_facing = 1",
        'Two additional engineers and an automated pipeline. Raises the whole estate rather than one host.',
    ],
];

$ins = $pdo->prepare(
    "INSERT INTO remediations
        (tenant_id, name, description, cost_inr, effort_days, control_key, effectiveness_target, eliminates, status)
     VALUES (?,?,?,?,?,?,?,?, 'proposed')"
);
$link = $pdo->prepare("INSERT IGNORE INTO remediation_findings (remediation_id, finding_id) VALUES (?,?)");

$total = 0;
foreach ($catalog as $c) {
    [$name, $cost, $days, $eliminates, $controlKey, $target, $where, $desc] = $c;

    $ins->execute([$tid, $name, $desc, $cost, $days, $controlKey, $target, $eliminates]);
    $rid = (int) $pdo->lastInsertId();

    $ids = $pdo->query(
        "SELECT f.id
           FROM findings f
           JOIN assets a          ON a.id = f.asset_id
           JOIN vulnerabilities v ON v.id = f.vulnerability_id
          WHERE f.tenant_id = $tid AND f.status = 'open' AND ($where)"
    )->fetchAll(PDO::FETCH_COLUMN);

    foreach ($ids as $fid) {
        $link->execute([$rid, (int) $fid]);
    }
    printf("  %-58s ₹%9s  %2d findings\n", mb_substr($name, 0, 58), number_format($cost), count($ids));
    $total++;
}

echo "\n$total remediation options seeded\n";
$orphans = (int) $pdo->query(
    "SELECT COUNT(*) FROM remediations r
      LEFT JOIN remediation_findings rf ON rf.remediation_id = r.id
      WHERE r.tenant_id = $tid AND rf.finding_id IS NULL"
)->fetchColumn();
if ($orphans) {
    echo "warning: $orphans option(s) matched no finding and can never be worth anything\n";
}
