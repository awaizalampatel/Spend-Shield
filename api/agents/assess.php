<?php
/**
 * Run the agent layer over the estate.
 *
 *   php api/agents/assess.php [--tenant=acme-in] [--limit=N] [--sweep]
 *
 * Scores every open finding with the deterministic engine, then has the owning
 * agent write the assessment — reusing one wherever an equivalent finding has
 * already been explained. Prints what it cost and what reuse saved.
 *
 * --sweep also runs the nightly roster hygiene afterwards.
 */
require_once __DIR__ . '/../config/db.php';
require_once __DIR__ . '/../risk/Portfolio.php';
require_once __DIR__ . '/Assessor.php';

$pdo    = db();
$tenant = 'acme-in';
$limit  = 0;
$sweep  = in_array('--sweep', $argv, true);
foreach ($argv as $a) {
    if (str_starts_with($a, '--tenant=')) { $tenant = substr($a, 9); }
    if (str_starts_with($a, '--limit='))  { $limit = (int) substr($a, 8); }
}

$inr = static function (float $x): string {
    if ($x >= 10000000) { return '₹' . number_format($x / 10000000, 2) . ' Cr'; }
    if ($x >= 100000)   { return '₹' . number_format($x / 100000, 2) . ' L'; }
    return '₹' . number_format($x, 0);
};

$p = Portfolio::load($pdo, $tenant);
$eval = $p->evaluate();

// Findings joined to everything the assessor needs, in one pass.
$rows = $pdo->prepare(
    "SELECT f.id, f.asset_id,
            a.hostname, a.os, a.asset_class, a.criticality, a.internet_facing,
            a.environment, a.pii_records,
            v.source, v.cve_id, v.local_key, v.title, v.description,
            v.cvss_score, v.cvss_vector, v.kev_listed, v.kev_ransomware,
            v.impact_c, v.impact_i, v.impact_a
       FROM findings f
       JOIN assets a          ON a.id = f.asset_id
       JOIN vulnerabilities v ON v.id = f.vulnerability_id
      WHERE f.tenant_id = ? AND f.status = 'open'
   ORDER BY f.id"
);
$rows->execute([$p->tenantId]);
$findings = $rows->fetchAll();
if ($limit > 0) {
    $findings = array_slice($findings, 0, $limit);
}

// Which controls sit on each asset — part of the shape, so it must be exact.
$controlsByAsset = [];
foreach ($p->controls as $aid => $set) {
    $controlsByAsset[$aid] = array_keys($set);
}

echo "\nAssessing ", count($findings), " findings for ", $tenant, "\n";
echo str_repeat('-', 92), "\n";
printf("%-4s %-16s %-26s %-10s %10s %s\n", 'ID', 'ASSET', 'AGENT', 'REUSE', 'COST', 'MS');

$stats = ['fresh' => 0, 'exact' => 0, 'semantic' => 0];
$created = [];
$merges = [];
$totalCost = 0.0;
$t0 = microtime(true);

foreach ($findings as $f) {
    OpenRouter::reset();
    $score = $p->evaluate()['scores'][$f['id']] ?? null;
    if (!$score) {
        // Re-score just this one rather than the whole estate.
        $score = RiskEngine::score($f, $f, $p->controls[(int) $f['asset_id']] ?? []);
    }
    $ale = (float) ($eval['per_finding'][$f['id']] ?? 0);

    $r = Assessor::assess(
        $pdo, $p->tenantId, $f, $score,
        ['ale' => $ale, 'display' => $inr($ale)],
        $controlsByAsset[(int) $f['asset_id']] ?? []
    );

    $stats[$r['reuse']] = ($stats[$r['reuse']] ?? 0) + 1;
    $totalCost += $r['cost'];
    if ($r['created_agent']) { $created[] = $r['agent_key']; }
    if ($r['merged'])        { $merges[] = $r['merged']; }

    printf("%-4d %-16s %-26s %-10s %10s %4dms\n",
        $f['id'], substr((string) $f['hostname'], 0, 16),
        substr($r['agent_key'], 0, 26), $r['reuse'],
        $r['cost'] > 0 ? '$' . number_format($r['cost'], 6) : '$0.00', $r['ms']);

    // Record the reuse type on the current score row, so the UI can show it.
    $pdo->prepare("UPDATE risk_scores SET agent_key = ?, reuse_type = ?, cost_usd = ?
                    WHERE finding_id = ? AND is_current = 1")
        ->execute([$r['agent_key'], $r['reuse'], $r['cost'], $f['id']]);

    $pdo->prepare("INSERT INTO experiences (tenant_id, finding_id, agent_key, reuse_type, model, latency_ms, cost_usd)
                   VALUES (?,?,?,?,?,?,?)")
        ->execute([$p->tenantId, $f['id'], $r['agent_key'], $r['reuse'], null, $r['ms'], $r['cost']]);
}

$elapsed = microtime(true) - $t0;
$reused = ($stats['exact'] ?? 0) + ($stats['semantic'] ?? 0);
$total = max(1, count($findings));

echo "\n", str_repeat('-', 92), "\n";
printf("%d findings in %.1fs\n", count($findings), $elapsed);
printf("  fresh    %3d\n", $stats['fresh'] ?? 0);
printf("  exact    %3d  (deterministic shape match, no API)\n", $stats['exact'] ?? 0);
printf("  semantic %3d  (embedding match)\n", $stats['semantic'] ?? 0);
printf("  reuse rate %.0f%%\n", $reused / $total * 100);
printf("\nspent      $%.6f\n", $totalCost);
// What the same run would have cost with no reuse, at the measured per-fresh
// rate. On a fully warm run there are no fresh assessments to average, so fall
// back to the historical rate from the experience log — otherwise a 100%-reuse
// run reports that it saved nothing, which is the opposite of the truth.
$perFresh = ($stats['fresh'] ?? 0) > 0 ? $totalCost / $stats['fresh'] : 0.0;
if ($perFresh <= 0) {
    $perFresh = (float) $pdo->query(
        "SELECT COALESCE(AVG(cost_usd),0) FROM experiences WHERE reuse_type = 'fresh' AND cost_usd > 0"
    )->fetchColumn();
}
printf("would have $%.6f without reuse  (saved $%.6f)\n", $perFresh * $total, $perFresh * $reused);

if ($created) {
    echo "\nagents created (", count($created), "):\n";
    foreach (array_slice($created, 0, 12) as $k) { echo "  ", $k, "\n"; }
}
if ($merges) {
    echo "\nmerged on creation (", count($merges), "):\n";
    foreach ($merges as $m) {
        printf("  %-28s -> %-24s %.3f (%s)\n", $m['from'], $m['into'], $m['similarity'] ?? 0, $m['method'] ?? '?');
    }
}

if ($sweep) {
    $s = AgentRegistry::dedupSweep($pdo, true);
    echo "\nnightly sweep: checked ", $s['checked'], ", merged ", count($s['merged']),
         ", retired ", count($s['retired']), "\n";
    foreach ($s['merged'] as $m) {
        printf("  %-28s -> %-24s %.3f\n", $m['from'], $m['into'], $m['similarity']);
    }
}

$roster = $pdo->query(
    "SELECT status, COUNT(*) n FROM agents WHERE kind='task' GROUP BY status"
)->fetchAll();
echo "\nroster: ";
foreach ($roster as $r) { echo $r['status'], ' ', $r['n'], '  '; }
echo "\n";
