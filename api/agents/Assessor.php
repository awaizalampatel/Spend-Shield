<?php
/**
 * Assessor — produces the written assessment for a finding, reusing one when an
 * equivalent finding has already been explained.
 *
 * This is where the agent layer meets the risk engine, and the division is
 * strict: the ENGINE produces the number, deterministically, with no model
 * anywhere near it. The ASSESSOR produces the words around that number — why it
 * matters here, what would close it, what to watch. A model may write the
 * explanation of a figure it did not compute.
 *
 * Every turn goes through the reuse ladder first, so the second identical
 * finding costs nothing and says so.
 */
require_once __DIR__ . '/OpenRouter.php';
require_once __DIR__ . '/RiskShape.php';
require_once __DIR__ . '/RiskTypeDeriver.php';
require_once __DIR__ . '/AgentRegistry.php';
require_once __DIR__ . '/AssessmentWarehouse.php';

class Assessor
{
    /**
     * Assess one finding.
     *
     * @param array $f       finding row joined to its asset and vulnerability
     * @param array $score   RiskEngine::score() output for the same finding
     * @param array $money   ['ale' => float, 'display' => string]
     * @param string[] $controlKeys controls present on the asset
     *
     * @return array{
     *   agent_key:string, agent_id:int, narrative:string, reuse:string,
     *   similarity:?float, cost:float, created_agent:bool, merged:?array, ms:int
     * }
     */
    public static function assess(
        PDO $pdo, int $tenantId, array $f, array $score, array $money, array $controlKeys, int $userId = 0
    ): array {
        $t0 = microtime(true);

        // 1 — which family is this, and which agent owns it
        $type  = RiskTypeDeriver::derive($pdo, $f, $f);
        $found = AgentRegistry::findOrCreate($pdo, $type, $userId);
        $agent = $found['agent'];
        $agentKey = (string) ($agent['agent_key'] ?? 'risk.unknown');

        // 2 — the reuse ladder
        $shapeText = RiskShape::shapeText($f, $f, $controlKeys);
        $shapeHash = RiskShape::shapeHash($f, $f, $controlKeys);
        $hit = AssessmentWarehouse::lookup($pdo, $tenantId, $agentKey, $shapeHash, $shapeText);

        if ($hit) {
            AgentRegistry::recordUse($pdo, (int) ($agent['id'] ?? 0), 0.0, true);
            return [
                'agent_key' => $agentKey,
                'agent_id'  => (int) ($agent['id'] ?? 0),
                'narrative' => (string) ($hit['payload']['narrative'] ?? ''),
                'reuse'     => $hit['depth'],
                'similarity'=> $hit['similarity'],
                'cost'      => 0.0,
                'created_agent' => false,
                'merged'    => $found['merged'],
                'ms'        => (int) ((microtime(true) - $t0) * 1000),
            ];
        }

        // 3 — nothing to reuse: write it
        $narrative = self::write($agent, $f, $score, $money, $controlKeys);
        $cost = OpenRouter::totalCost();

        if ($narrative !== '') {
            AssessmentWarehouse::store(
                $pdo, $tenantId, $agentKey, $shapeHash, $shapeText,
                ['narrative' => $narrative, 'written_at' => date('c')],
                !empty($f['kev_listed'])
            );
        }

        AgentRegistry::recordUse($pdo, (int) ($agent['id'] ?? 0), $cost, false);

        return [
            'agent_key' => $agentKey,
            'agent_id'  => (int) ($agent['id'] ?? 0),
            'narrative' => $narrative,
            'reuse'     => 'fresh',
            'similarity'=> null,
            'cost'      => $cost,
            'created_agent' => $found['created'],
            'merged'    => $found['merged'],
            'ms'        => (int) ((microtime(true) - $t0) * 1000),
        ];
    }

    /**
     * The generation step. The agent's own template shapes the answer, which is
     * what makes two agents assess their families differently rather than every
     * finding coming back in the same voice.
     */
    private static function write(array $agent, array $f, array $score, array $money, array $controlKeys): string
    {
        if (!OpenRouter::enabled()) {
            return '';
        }

        // The model is given the computed figures — it explains them, it does
        // not produce them. Note the instruction never to restate the number
        // differently: the arithmetic on screen is the authority.
        $facts = implode("\n", [
            'Weakness: ' . (string) ($f['title'] ?? ''),
            'Identifier: ' . (string) ($f['cve_id'] ?? $f['local_key'] ?? 'n/a'),
            'Asset: ' . (string) ($f['hostname'] ?? '') . ' — ' . (string) ($f['asset_class'] ?? ''),
            'Operating system: ' . (string) ($f['os'] ?? 'unknown'),
            'Reachable from: ' . RiskShape::exposure($f),
            'CVSS: ' . (string) ($f['cvss_score'] ?? 'unrated'),
            'Exploited in the wild: ' . (!empty($f['kev_listed'])
                ? 'yes' . (!empty($f['kev_ransomware']) ? ', linked to ransomware campaigns' : '') : 'no'),
            'Exploitation probability (annualized): ' . number_format((float) $score['threat_probability'], 3),
            'Controls in front of it: ' . ($controlKeys ? implode(', ', $controlKeys) : 'none'),
            'Residual control gap: ' . number_format((float) $score['control_gap'], 2),
            'Computed annualized loss: ' . (string) ($money['display'] ?? ''),
        ]);

        $res = OpenRouter::chat((string) ($agent['model_id'] ?? OpenRouter::CHEAP), [
            ['role' => 'system', 'content' =>
                ((string) ($agent['template'] ?? 'Assess this finding.')) . "\n\n"
                . 'Write 2-3 sentences for a security lead who has to decide whether to fund a fix. '
                . 'State plainly why this matters ON THIS ASSET, and what would close it. '
                . 'The loss figure was computed deterministically and is given to you — you may refer '
                . 'to it, but never restate it as a different number and never invent a new one. '
                . 'No headings, no bullet points, no preamble.'],
            ['role' => 'user', 'content' => $facts],
        ], ['max_tokens' => 200, 'temperature' => 0.2], 'assessment');

        return $res['error'] === null ? $res['content'] : '';
    }
}
