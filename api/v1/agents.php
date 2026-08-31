<?php
/**
 * GET /api/v1/agents.php            the roster + reuse statistics
 * GET /api/v1/agents.php?key=risk.x one agent, with its assessments
 *
 * This endpoint is the system's own workings, on the record: every specialist it
 * created for itself, what each cost, how much work reuse avoided, and which
 * agents were merged away and why.
 */
require_once __DIR__ . '/_boot.php';
require_once __DIR__ . '/../agents/AgentRegistry.php';
require_once __DIR__ . '/../agents/AssessmentWarehouse.php';

$pdo  = db();
$user = currentUser($pdo);
$tid  = (int) $user['tenant_id'];
AgentRegistry::ensure($pdo);

$key = trim((string) ($_GET['key'] ?? ''));

// ------------------------------------------------------------- one agent
if ($key !== '') {
    $a = AgentRegistry::getByKey($pdo, $key, false);
    if (!$a) {
        fail(404, 'No agent by that key.');
    }

    $work = $pdo->prepare(
        "SELECT f.id AS finding_id, a2.hostname, COALESCE(v.cve_id, v.local_key) AS ref,
                v.title, rs.ale_likely, rs.reuse_type, rs.cost_usd, rs.computed_at
           FROM risk_scores rs
           JOIN findings f        ON f.id = rs.finding_id
           JOIN assets a2         ON a2.id = f.asset_id
           JOIN vulnerabilities v ON v.id = f.vulnerability_id
          WHERE rs.tenant_id = ? AND rs.is_current = 1 AND rs.agent_key = ?
       ORDER BY rs.ale_likely DESC LIMIT 40"
    );
    $work->execute([$tid, (string) $a['agent_key']]);

    $samples = $pdo->prepare(
        "SELECT shape_text, payload, hits, created_at, expires_at
           FROM assessment_warehouse
          WHERE tenant_id = ? AND agent_key = ?
       ORDER BY hits DESC, id DESC LIMIT 5"
    );
    $samples->execute([$tid, (string) $a['agent_key']]);

    $aliases = $pdo->prepare(
        "SELECT agent_key, name FROM agents WHERE merged_into = ?"
    );
    $aliases->execute([(string) $a['agent_key']]);

    ok([
        'agent' => agentRow($a),
        'assessments' => array_map(static fn($r) => [
            'finding_id' => (int) $r['finding_id'],
            'asset' => $r['hostname'],
            'ref' => $r['ref'],
            'title' => $r['title'],
            'loss' => money((float) $r['ale_likely']),
            'reuse' => $r['reuse_type'],
            'cost_usd' => (float) $r['cost_usd'],
            'at' => $r['computed_at'],
        ], $work->fetchAll()),
        'written' => array_map(static function ($r) {
            $p = json_decode((string) $r['payload'], true) ?: [];
            return [
                'shape' => $r['shape_text'],
                'narrative' => (string) ($p['narrative'] ?? ''),
                'replays' => (int) $r['hits'],
                'written_at' => $r['created_at'],
                'expires_at' => $r['expires_at'],
            ];
        }, $samples->fetchAll()),
        'merged_in' => array_map(static fn($r) => [
            'key' => $r['agent_key'], 'name' => $r['name'],
        ], $aliases->fetchAll()),
    ]);
}

// ---------------------------------------------------------------- roster
$rows = $pdo->query(
    "SELECT * FROM agents ORDER BY kind DESC, uses DESC, agent_key"
)->fetchAll();

$control = [];
$task = [];
$merged = [];
foreach ($rows as $r) {
    if (!empty($r['merged_into'])) {
        $merged[] = [
            'key' => $r['agent_key'], 'name' => $r['name'],
            'into' => $r['merged_into'], 'uses' => (int) $r['uses'],
        ];
        continue;
    }
    if ($r['kind'] === 'control') { $control[] = agentRow($r); }
    else                          { $task[] = agentRow($r); }
}

// Reuse economics, from the experience log — measured, never estimated.
$exp = $pdo->prepare(
    "SELECT reuse_type, COUNT(*) n, COALESCE(SUM(cost_usd),0) cost, COALESCE(AVG(latency_ms),0) ms
       FROM experiences WHERE tenant_id = ? GROUP BY reuse_type"
);
$exp->execute([$tid]);
$byReuse = [];
$total = 0; $spent = 0.0;
foreach ($exp as $r) {
    $byReuse[$r['reuse_type']] = [
        'count' => (int) $r['n'],
        'cost' => round((float) $r['cost'], 6),
        'avg_ms' => (int) round((float) $r['ms']),
    ];
    $total += (int) $r['n'];
    $spent += (float) $r['cost'];
}
$reused = ($byReuse['exact']['count'] ?? 0) + ($byReuse['semantic']['count'] ?? 0);
$freshCount = $byReuse['fresh']['count'] ?? 0;
$perFresh = $freshCount > 0 ? ($byReuse['fresh']['cost'] ?? 0) / $freshCount : 0.0;

ok([
    'summary' => [
        'control_agents' => count($control),
        'task_agents'    => count($task),
        'merged'         => count($merged),
        'active'         => count(array_filter($task, static fn($a) => $a['status'] === 'active')),
        'canary'         => count(array_filter($task, static fn($a) => $a['status'] === 'canary')),
        'deprecated'     => count(array_filter($task, static fn($a) => $a['status'] === 'deprecated')),
        'assessments'    => $total,
        'reuse_rate'     => $total > 0 ? round($reused / $total * 100, 1) : 0.0,
        'spent_usd'      => round($spent, 6),
        'saved_usd'      => round($perFresh * $reused, 6),
        'by_reuse'       => $byReuse,
    ],
    'warehouse' => AssessmentWarehouse::stats($pdo, $tid),
    'control_plane' => $control,
    'agents' => $task,
    'merged' => $merged,
    // Stated on the page rather than buried: the semantic depth of the ladder
    // is unavailable without an embedding key, and the roster reflects that.
    'notice' => AssessmentWarehouse::stats($pdo, $tid)['semantic_available']
        ? null
        : 'Semantic matching is off — no embedding key is configured, so reuse runs on exact '
        . 'shape matching only and paraphrased duplicate agents are not merged yet.',
]);

function agentRow(array $r): array
{
    return [
        'key'         => $r['agent_key'],
        'kind'        => $r['kind'],
        'origin'      => $r['origin'],
        'name'        => $r['name'],
        'description' => $r['description'],
        'lane'        => $r['category'],
        'subject'     => $r['family_subject'] ?? null,
        'model'       => $r['model_id'],
        'tier'        => $r['model_tier'],
        'status'      => $r['status'],
        'pinned'      => (bool) $r['pinned'],
        'version'     => (int) $r['version'],
        'quality'     => $r['quality_score'] !== null ? (float) $r['quality_score'] : null,
        'uses'        => (int) $r['uses'],
        'reused'      => (int) $r['cache_hits'],
        'reuse_rate'  => ((int) $r['uses']) > 0
            ? round((int) $r['cache_hits'] / (int) $r['uses'] * 100) : 0,
        'cost_usd'    => round((float) $r['cost_usd'], 6),
        'template'    => $r['template'],
        'created_at'  => $r['created_at'],
    ];
}
