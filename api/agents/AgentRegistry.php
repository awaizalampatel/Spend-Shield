<?php
/**
 * AgentRegistry — an agent is a row, not a process.
 *
 * A risk agent is a stored capability: a name, a description, the model it uses,
 * a quality record and a usage count. "Running" one means loading the row and
 * letting the assessment pipeline use it. That is what makes agents cheap enough
 * to create per risk family, free to reuse, and possible to merge.
 *
 * DEDUP IS THE POINT. The deriver names the same job many ways — it produced
 * "MFA Privileged Access" and "MFA Privileged Accounts" within one run of the
 * demo estate. Left alone the roster fills with twins, each carrying a diluted
 * quality score, and the registry becomes noise. So creation always checks for
 * an existing agent doing the same job first, and a duplicate slug is left as a
 * forwarding alias rather than a second row.
 *
 * Two similarity paths, and the fallback is not a token gesture:
 *   embeddings  when a Jina key with balance is configured (better on paraphrase)
 *   lexical     token overlap, always available
 * Thresholds for both are measured, not inherited — see docs/calibration.md.
 */
require_once __DIR__ . '/Embeddings.php';
require_once __DIR__ . '/RiskShape.php';

class AgentRegistry
{
    /**
     * Semantic merge threshold. Measured on this domain's agent descriptions:
     * twins landed 0.53-0.67, the closest non-twin at 0.45. soundd.ai's 0.80,
     * carried over unchanged, would have caught none of them.
     */
    public const MERGE_SIM = 0.50;

    /**
     * Lexical merge threshold (Dice coefficient over name+description tokens).
     * "MFA Privileged Access" vs "MFA Privileged Accounts" scores 0.67 on names
     * alone; unrelated families score under 0.15. 0.55 sits in that gap.
     */
    public const MERGE_LEX = 0.55;

    /** A dynamic agent with enough uses to judge, stuck under the quality floor. */
    private const WEAK_USES = 12;
    private const WEAK_QUALITY = 4.0;

    /**
     * The fixed control-plane agents. These already exist as code — this row is
     * their registry entry and governance record, not new logic. Naming them
     * here is what lets the /agents page show the whole system, not half of it.
     */
    private const CONTROL_AGENTS = [
        ['control.shape',      'Shape',      'Reduces a finding to its reusable signature, so identical problems are recognised without a model call.', 'RiskShape'],
        ['control.deriver',    'Deriver',    'Names a new risk family from the finding that first revealed it. One cheap call, cached by family.', 'RiskTypeDeriver'],
        ['control.registry',   'Registry',   'Finds, creates, merges and retires risk agents.', 'AgentRegistry'],
        ['control.warehouse',  'Warehouse',  'Replays a stored assessment when an equivalent finding has already been scored.', 'AssessmentWarehouse'],
        ['control.engine',     'Engine',     'Computes the deterministic five-factor score. No model is involved in the money path.', 'RiskEngine'],
        ['control.optimizer',  'Optimizer',  'Chooses the remediations that remove the most exposure inside a budget.', 'Optimizer'],
    ];

    private static bool $ensured = false;

    /** Seed the control plane once. Idempotent. */
    public static function ensure(PDO $pdo): void
    {
        if (self::$ensured) {
            return;
        }
        self::$ensured = true;
        $ins = $pdo->prepare(
            "INSERT INTO agents (agent_key, kind, origin, name, description, category, model_id, status, pinned)
             VALUES (?, 'control', 'fixed', ?, ?, 'control', NULL, 'active', 1)
             ON DUPLICATE KEY UPDATE description = VALUES(description)"
        );
        foreach (self::CONTROL_AGENTS as [$key, $name, $desc, $impl]) {
            $ins->execute([$key, $name, $desc . ' (' . $impl . ')']);
        }
    }

    /** Look up an agent, following a merge to the surviving row. */
    public static function getByKey(PDO $pdo, string $key, bool $followMerge = true): ?array
    {
        $q = $pdo->prepare("SELECT * FROM agents WHERE agent_key = ?");
        $q->execute([$key]);
        $a = $q->fetch();
        if (!$a) {
            return null;
        }
        if ($followMerge && !empty($a['merged_into'])) {
            // One hop only. A merge chain would mean a bug elsewhere, and
            // following it blindly is how you get an infinite loop in production.
            $q->execute([$a['merged_into']]);
            return $q->fetch() ?: $a;
        }
        return $a;
    }

    /**
     * Find an existing agent that already does this job.
     *
     * @return array|null the survivor row, or null when this is genuinely new
     */
    /**
     * THE SUBJECT GUARD. Name similarity alone is not evidence that two agents
     * do the same job. Run against the real estate it merged MOVEit into Log4j
     * (0.571), SAP into Exchange (0.588) and Linux into Windows (0.560) — all
     * because derived names share the words "software" and "vulnerabilities".
     *
     * So a merge now requires the two agents to own the SAME technology family,
     * which is a deterministic fact off the finding, not a guess about wording.
     * Similarity only decides among candidates that already pass that test.
     */
    public static function findSimilar(PDO $pdo, string $name, string $description, ?string $subject = null): ?array
    {
        if ($subject === null || $subject === '') {
            return null;   // no subject, no merge — never guess across families
        }
        $q = $pdo->prepare(
            "SELECT * FROM agents
              WHERE kind = 'task' AND merged_into IS NULL
                AND status NOT IN ('retired') AND family_subject = ?"
        );
        $q->execute([$subject]);
        $rows = $q->fetchAll();
        if (!$rows) {
            return null;
        }

        $mine = trim($name . '. ' . $description);

        // --- semantic path, when embeddings are available
        if (Embeddings::enabled()) {
            $texts = [$mine];
            foreach ($rows as $r) {
                $texts[] = trim(((string) $r['name']) . '. ' . ((string) $r['description']));
            }
            $vecs = Embeddings::embedMany($pdo, $texts);
            if (is_array($vecs[0] ?? null)) {
                $best = null; $bestSim = 0.0;
                foreach ($rows as $i => $r) {
                    $sim = Embeddings::cosine($vecs[0], $vecs[$i + 1] ?? null);
                    if ($sim > $bestSim) { $bestSim = $sim; $best = $r; }
                }
                if ($best && $bestSim >= self::MERGE_SIM) {
                    $best['_similarity'] = round($bestSim, 4);
                    $best['_method'] = 'embedding';
                    return $best;
                }
                return null;   // embeddings spoke; do not second-guess with lexical
            }
            // fell through: the API failed, so use the lexical path below
        }

        // --- lexical path
        $best = null; $bestSim = 0.0;
        foreach ($rows as $r) {
            $sim = self::dice($mine, trim(((string) $r['name']) . '. ' . ((string) $r['description'])));
            if ($sim > $bestSim) { $bestSim = $sim; $best = $r; }
        }
        if ($best && $bestSim >= self::MERGE_LEX) {
            $best['_similarity'] = round($bestSim, 4);
            $best['_method'] = 'lexical';
            return $best;
        }
        return null;
    }

    /**
     * Dice coefficient over content tokens. Crude next to an embedding, but it
     * catches the failure that actually happens here — the same job named with
     * one word changed — and it never stops working.
     */
    public static function dice(string $a, string $b): float
    {
        $ta = self::tokens($a);
        $tb = self::tokens($b);
        if (!$ta || !$tb) {
            return 0.0;
        }
        $shared = count(array_intersect($ta, $tb));
        return (2 * $shared) / (count($ta) + count($tb));
    }

    private const STOPWORDS = ['a','an','the','of','on','to','in','for','and','or','is','are','that',
                               'this','with','from','by','it','its','as','at','be','can','which','when'];

    /** @return string[] deduplicated, stemmed content words */
    private static function tokens(string $s): array
    {
        $s = strtolower(preg_replace('/[^a-z0-9 ]+/i', ' ', $s));
        $out = [];
        foreach (preg_split('/\s+/', $s, -1, PREG_SPLIT_NO_EMPTY) as $w) {
            if (strlen($w) < 3 || in_array($w, self::STOPWORDS, true)) {
                continue;
            }
            // Crude stemming, enough to make account/accounts and
            // vulnerability/vulnerabilities the same token.
            $w = preg_replace('/(ies)$/', 'y', $w);
            $w = preg_replace('/(es|s)$/', '', $w);
            $out[$w] = true;
        }
        return array_keys($out);
    }

    /**
     * Find or create the agent for a risk family.
     *
     * @param array $type RiskTypeDeriver::derive() output
     * @return array{agent:array, created:bool, merged:?array}
     */
    public static function findOrCreate(PDO $pdo, array $type, int $userId = 0): array
    {
        self::ensure($pdo);
        $key = 'risk.' . $type['slug'];

        if ($existing = self::getByKey($pdo, $key)) {
            return ['agent' => $existing, 'created' => false, 'merged' => null];
        }

        // Does something already do this job under another name?
        $dup = self::findSimilar($pdo, $type['name'], $type['description'], $type['subject'] ?? null);
        if ($dup) {
            // Leave a forwarding row. Without it this slug misses forever and
            // pays the similarity scan again on every future finding of this shape.
            self::createAlias($pdo, $key, (string) $dup['agent_key'], $type);
            return ['agent' => $dup, 'created' => false, 'merged' => [
                'from' => $key,
                'into' => $dup['agent_key'],
                'similarity' => $dup['_similarity'] ?? null,
                'method' => $dup['_method'] ?? null,
            ]];
        }

        $created = self::createDynamic($pdo, $key, $type, $userId);
        return ['agent' => $created, 'created' => true, 'merged' => null];
    }

    /** Model per lane — a cheap family never lands on an expensive model. */
    private const LANE_MODEL = [
        'configuration'          => ['google/gemini-2.5-flash-lite', 'cheap'],
        'vulnerability'          => ['google/gemini-2.5-flash', 'standard'],
        'exploited'              => ['google/gemini-2.5-flash', 'standard'],
        'operational_technology' => ['google/gemini-2.5-flash', 'standard'],
    ];

    public static function createDynamic(PDO $pdo, string $key, array $type, int $userId = 0): array
    {
        [$model, $tier] = self::LANE_MODEL[$type['lane'] ?? 'vulnerability']
            ?? self::LANE_MODEL['vulnerability'];

        $pdo->prepare(
            "INSERT INTO agents
                (agent_key, kind, origin, name, description, category, family_subject, template,
                 model_id, model_tier, status, created_by_user_id)
             VALUES (?, 'task', 'dynamic', ?, ?, ?, ?, ?, ?, ?, 'canary', ?)
             ON DUPLICATE KEY UPDATE name = VALUES(name)"
        )->execute([
            $key, $type['name'], $type['description'], $type['lane'] ?? 'vulnerability',
            $type['subject'] ?? null, self::seedTemplate($type), $model, $tier, $userId ?: null,
        ]);

        return self::getByKey($pdo, $key, false) ?? [];
    }

    /**
     * The starting instruction for a new agent. v1 seeds only — once the tuning
     * loop exists these evolve from real quality signal.
     */
    private static function seedTemplate(array $type): string
    {
        return 'Assess ' . lcfirst((string) $type['name']) . '. '
            . 'Establish reachability from scan evidence before scoring. Weight an active-exploitation '
            . 'listing above the CVSS base score. Name the compensating control that would close the gap '
            . 'and its observed effectiveness on this asset. Never assert a probability without naming '
            . 'its source.';
    }

    public static function createAlias(PDO $pdo, string $key, string $survivor, array $type): void
    {
        $pdo->prepare(
            "INSERT INTO agents
                (agent_key, kind, origin, name, description, status, merged_into)
             VALUES (?, 'task', 'dynamic', ?, ?, 'deprecated', ?)
             ON DUPLICATE KEY UPDATE merged_into = VALUES(merged_into)"
        )->execute([$key, $type['name'], $type['description'], $survivor]);
    }

    /**
     * Record one use. Usage and cost are facts; quality is a rolling average
     * once something is actually grading answers.
     */
    public static function recordUse(PDO $pdo, int $agentId, float $costUsd, bool $reused, ?float $quality = null): void
    {
        if ($agentId <= 0) {
            return;
        }
        $pdo->prepare(
            "UPDATE agents
                SET uses = uses + 1,
                    cache_hits = cache_hits + ?,
                    cost_usd = cost_usd + ?,
                    quality_score = CASE
                        WHEN ? IS NULL THEN quality_score
                        WHEN quality_score IS NULL THEN ?
                        ELSE ROUND(quality_score * 0.8 + ? * 0.2, 2) END
              WHERE id = ?"
        )->execute([$reused ? 1 : 0, $costUsd, $quality, $quality, $quality, $agentId]);

        // Lifecycle: a canary that has proved itself becomes active.
        $pdo->prepare(
            "UPDATE agents SET status = 'active'
              WHERE id = ? AND origin = 'dynamic' AND status = 'canary' AND uses >= 5
                AND (quality_score IS NULL OR quality_score >= 6.0)"
        )->execute([$agentId]);

        // And one that is chronically weak is demoted. Status flips only —
        // never a delete, because the usage record is evidence.
        $pdo->prepare(
            "UPDATE agents SET status = 'deprecated'
              WHERE id = ? AND origin = 'dynamic' AND pinned = 0
                AND status IN ('active','canary') AND uses >= ?
                AND quality_score IS NOT NULL AND quality_score < ?"
        )->execute([$agentId, self::WEAK_USES, self::WEAK_QUALITY]);
    }

    /**
     * Nightly hygiene: merge agents that turned out to do the same job, and
     * retire the chronically weak. Off the request path.
     *
     * @return array{merged:array,retired:array,checked:int}
     */
    public static function dedupSweep(PDO $pdo, bool $apply = false): array
    {
        self::ensure($pdo);
        $rows = $pdo->query(
            "SELECT * FROM agents
              WHERE kind = 'task' AND merged_into IS NULL AND status <> 'retired'
           ORDER BY uses DESC, id ASC"
        )->fetchAll();

        $merged = [];
        $survivors = [];
        foreach ($rows as $r) {
            $mine = trim(((string) $r['name']) . '. ' . ((string) $r['description']));
            $hit = null;
            foreach ($survivors as $s) {
                // Same guard as creation: different technology families never merge,
                // however similar their names read.
                if ((string) $s['family_subject'] === '' || $s['family_subject'] !== $r['family_subject']) {
                    continue;
                }
                $sim = self::dice($mine, trim(((string) $s['name']) . '. ' . ((string) $s['description'])));
                if ($sim >= self::MERGE_LEX) {
                    $hit = ['into' => $s, 'sim' => $sim];
                    break;
                }
            }
            if ($hit) {
                // The more-used agent survives — it carries the longer record.
                $merged[] = [
                    'from' => $r['agent_key'], 'into' => $hit['into']['agent_key'],
                    'similarity' => round($hit['sim'], 4),
                    'uses_moved' => (int) $r['uses'],
                ];
                if ($apply) {
                    $pdo->prepare(
                        "UPDATE agents SET merged_into = ?, status = 'deprecated' WHERE id = ?"
                    )->execute([$hit['into']['agent_key'], $r['id']]);
                    $pdo->prepare("UPDATE agents SET uses = uses + ? WHERE id = ?")
                        ->execute([(int) $r['uses'], $hit['into']['id']]);
                }
            } else {
                $survivors[] = $r;
            }
        }

        $retired = $pdo->query(
            "SELECT agent_key, uses, quality_score FROM agents
              WHERE kind = 'task' AND origin = 'dynamic' AND pinned = 0
                AND merged_into IS NULL AND status = 'deprecated'
                AND uses >= " . self::WEAK_USES . "
                AND quality_score IS NOT NULL AND quality_score < " . self::WEAK_QUALITY
        )->fetchAll();

        if ($apply && $retired) {
            $pdo->exec(
                "UPDATE agents SET status = 'retired'
                  WHERE kind = 'task' AND origin = 'dynamic' AND pinned = 0
                    AND merged_into IS NULL AND status = 'deprecated'
                    AND uses >= " . self::WEAK_USES . "
                    AND quality_score IS NOT NULL AND quality_score < " . self::WEAK_QUALITY
            );
        }

        return ['merged' => $merged, 'retired' => $retired, 'checked' => count($rows)];
    }
}
