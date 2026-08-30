<?php
/**
 * Recompute every open finding's risk and money figure.
 *
 *   php api/risk/recompute.php --tenant=acme-in [--quiet]
 *
 * Two passes, because loss is valued per ASSET, not per finding:
 *   1. score every finding      (RiskEngine, deterministic)
 *   2. per asset, combine those scores into one expected loss and hand each
 *      finding its share    (Aggregator + LossModel)
 *
 * Writes one risk_scores row per finding and retires the previous one
 * (is_current = 0) rather than updating it — the history IS the exposure trend,
 * and overwriting it would throw away the only evidence the budget worked.
 */
require_once __DIR__ . '/../config/db.php';
require_once __DIR__ . '/RiskEngine.php';
require_once __DIR__ . '/LossModel.php';
require_once __DIR__ . '/Aggregator.php';

$pdo    = db();
$tenant = 'acme-in';
$quiet  = in_array('--quiet', $argv, true);
foreach ($argv as $a) {
    if (str_starts_with($a, '--tenant=')) { $tenant = substr($a, 9); }
}

$t = $pdo->prepare("SELECT id, name FROM tenants WHERE slug = ?");
$t->execute([$tenant]);
$tRow = $t->fetch();
if (!$tRow) {
    fwrite(STDERR, "no such tenant: $tenant\n");
    exit(1);
}
$tid = (int) $tRow['id'];

$m = $pdo->prepare("SELECT * FROM loss_models WHERE tenant_id = ? AND is_active = 1 ORDER BY version DESC LIMIT 1");
$m->execute([$tid]);
$model = $m->fetch();
if (!$model) {
    fwrite(STDERR, "tenant $tenant has no active loss model\n");
    exit(1);
}

// Controls per asset, observed effectiveness preferred over the vendor claim.
$controlsByAsset = [];
$cq = $pdo->prepare(
    "SELECT ac.asset_id, c.control_key, c.claimed_effectiveness, c.observed_effectiveness
       FROM asset_controls ac
       JOIN controls c ON c.id = ac.control_id
      WHERE c.tenant_id = ? AND ac.status <> 'absent'"
);
$cq->execute([$tid]);
foreach ($cq as $r) {
    $observed = $r['observed_effectiveness'] !== null;
    $controlsByAsset[(int) $r['asset_id']][$r['control_key']] = [
        'effectiveness' => (float) ($observed ? $r['observed_effectiveness'] : $r['claimed_effectiveness']),
        'observed'      => $observed,
    ];
}

$fq = $pdo->prepare(
    "SELECT f.id AS finding_id, f.asset_id,
            a.hostname, a.criticality, a.internet_facing, a.environment,
            a.revenue_per_hour, a.pii_records,
            v.id AS vuln_id, v.cve_id, v.local_key, v.source, v.title, v.description,
            v.cvss_score, v.cvss_version, v.cvss_vector,
            v.epss_score, v.epss_asof, v.kev_listed, v.kev_ransomware,
            v.impact_c, v.impact_i, v.impact_a
       FROM findings f
       JOIN assets a          ON a.id = f.asset_id
       JOIN vulnerabilities v ON v.id = f.vulnerability_id
      WHERE f.tenant_id = ? AND f.status = 'open' AND a.decommissioned_at IS NULL"
);
$fq->execute([$tid]);
$rows = $fq->fetchAll();

$before = (float) $pdo->query(
    "SELECT COALESCE(SUM(ale_likely),0) FROM risk_scores WHERE tenant_id = $tid AND is_current = 1"
)->fetchColumn();

$t0 = microtime(true);

// ---- pass 1: score every finding, group by asset
$byAsset = [];
$scored  = [];
foreach ($rows as $r) {
    $s = RiskEngine::score($r, $r, $controlsByAsset[(int) $r['asset_id']] ?? []);
    $scored[$r['finding_id']] = ['row' => $r, 'score' => $s];
    $byAsset[(int) $r['asset_id']][] = [
        'id'       => (int) $r['finding_id'],
        'raw_risk' => $s['raw_risk'],
        'channels' => [
            'availability'    => (bool) $r['impact_a'],
            'confidentiality' => (bool) $r['impact_c'],
            'integrity'       => (bool) $r['impact_i'],
        ],
    ];
}

// ---- pass 2: value each asset once, split it across that asset's findings
$aleFor = [];
$assetTotals = [];
foreach ($byAsset as $assetId => $list) {
    $asset = null;
    foreach ($scored as $s) {
        if ((int) $s['row']['asset_id'] === $assetId) { $asset = $s['row']; break; }
    }
    $loss = LossModel::channels($asset, $model);
    $agg  = Aggregator::forAsset($list, $loss);
    $assetTotals[] = ['hostname' => $asset['hostname'], 'ale' => $agg['asset_ale']];
    foreach ($agg['per_finding'] as $fid => $ale) {
        $aleFor[$fid] = $ale;
    }
}

$retire = $pdo->prepare("UPDATE risk_scores SET is_current = 0 WHERE finding_id = ? AND is_current = 1");
$ins = $pdo->prepare(
    "INSERT INTO risk_scores
        (finding_id, tenant_id, loss_model_version, severity_factor, threat_probability,
         asset_criticality, exposure_factor, control_gap, raw_risk,
         sle, ale_likely, ale_min, ale_max, confidence, agent_key, reuse_type, is_current)
     VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?, 'fresh', 1)"
);

$total = 0.0;
$pdo->beginTransaction();
foreach ($scored as $fid => $s) {
    $r = $s['row'];
    $sc = $s['score'];
    $ale = (float) ($aleFor[$fid] ?? 0);
    $band = LossModel::band($ale, (float) $sc['confidence']);
    // SLE stored per finding = what the asset loses if this finding lands, i.e.
    // the ALE divided back out by its own probability. Shown on the detail page.
    $sle = $sc['raw_risk'] > 0 ? $ale / $sc['raw_risk'] : 0.0;

    $retire->execute([$fid]);
    $ins->execute([
        $fid, $tid, $model['version'],
        $sc['severity_factor'], $sc['threat_probability'], $sc['asset_criticality'],
        $sc['exposure_factor'], $sc['control_gap'], $sc['raw_risk'],
        round($sle, 2), round($ale, 2), $band['min'], $band['max'],
        $sc['confidence'],
        // Phase 5 replaces this with the agent that actually handled the finding.
        'risk.' . ($r['source'] === 'config' ? 'configuration' : 'vulnerability'),
    ]);
    $total += $ale;
}
$pdo->commit();
$ms = (int) ((microtime(true) - $t0) * 1000);

$delta = $total - $before;
$pdo->prepare("INSERT INTO audit_log (tenant_id, actor, action, entity_type, entity_ref, before_value, after_value, money_effect, note)
               VALUES (?,'system','Exposure recomputed','tenant',?,?,?,?,?)")
    ->execute([$tid, $tenant, round($before, 2), round($total, 2), round($delta, 2),
               count($rows) . ' findings scored against loss model v' . $model['version']]);

if ($quiet) {
    echo round($total, 2), "\n";
    exit(0);
}

$inr = static function (float $x): string {
    if ($x >= 10000000)  { return '₹' . number_format($x / 10000000, 2) . ' Cr'; }
    if ($x >= 100000)    { return '₹' . number_format($x / 100000, 2) . ' L'; }
    return '₹' . number_format($x, 0);
};

echo "\n", $tRow['name'], " — loss model v", $model['version'], "\n";
echo str_repeat('-', 78), "\n";
echo count($rows), " findings across ", count($byAsset), " assets, scored in {$ms}ms\n";
echo "Annualized exposure: ", $inr($total),
     ($before > 0 ? '   (was ' . $inr($before) . ', ' . ($delta >= 0 ? '+' : '−') . $inr(abs($delta)) . ')' : ''), "\n\n";

$top = $pdo->query(
    "SELECT a.hostname, COALESCE(v.cve_id, v.local_key) AS ref, v.cvss_score,
            rs.threat_probability, rs.exposure_factor, rs.control_gap, rs.raw_risk, rs.ale_likely
       FROM risk_scores rs
       JOIN findings f        ON f.id = rs.finding_id
       JOIN assets a          ON a.id = f.asset_id
       JOIN vulnerabilities v ON v.id = f.vulnerability_id
      WHERE rs.tenant_id = $tid AND rs.is_current = 1
      ORDER BY rs.ale_likely DESC LIMIT 10"
)->fetchAll();

printf("%-16s %-22s %5s %6s %5s %5s %7s %13s\n", 'ASSET', 'WEAKNESS', 'CVSS', 'THREAT', 'EXPO', 'GAP', 'RAW', 'ANNUAL LOSS');
foreach ($top as $r) {
    printf(
        "%-16s %-22s %5s %6.2f %5.2f %5.2f %7.4f %13s\n",
        $r['hostname'], substr($r['ref'], 0, 22), $r['cvss_score'],
        $r['threat_probability'], $r['exposure_factor'], $r['control_gap'],
        $r['raw_risk'], $inr((float) $r['ale_likely'])
    );
}

usort($assetTotals, static fn($x, $y) => $y['ale'] <=> $x['ale']);
echo "\nBy asset:\n";
foreach (array_slice($assetTotals, 0, 6) as $a) {
    printf("  %-16s %13s\n", $a['hostname'], $inr((float) $a['ale']));
}

$band = $pdo->query(
    "SELECT COALESCE(SUM(ale_min),0) lo, COALESCE(SUM(ale_max),0) hi
       FROM risk_scores WHERE tenant_id = $tid AND is_current = 1"
)->fetch();
$revenue = (float) $model['revenue_per_hour'] * 24 * 365;
echo "\nBand: ", $inr((float) $band['lo']), " — ", $inr((float) $band['hi']), "\n";
echo "Exposure as a share of annual revenue (", $inr($revenue), "): ",
     number_format($total / max(1, $revenue) * 100, 1), "%\n";
