<?php
/**
 * AssessmentWarehouse — the reuse ladder.
 *
 * WHAT IS ACTUALLY BEING REUSED. Not the arithmetic: the five-factor score runs
 * over the whole estate in about 50ms and caching it would save nothing. What
 * costs money is the written assessment — the paragraph that explains to a human
 * why this finding matters and what to do about it. That is a model call, and
 * the second identical finding should not pay for it twice.
 *
 * Two depths, cheapest first:
 *
 *   1 EXACT      same shape hash. A deterministic key over the finding's
 *                structure, so it needs no API and cannot drift. This is the
 *                common case: an estate repeats itself constantly.
 *
 *   2 SEMANTIC   an equivalent shape, by embedding similarity. Catches the
 *                near-miss the exact key steps over — one different control,
 *                a neighbouring severity band. Requires an embedding key; when
 *                there is none, the ladder simply stops at depth 1 rather than
 *                failing.
 *
 * Entries expire, because an assessment written before a CVE entered the KEV
 * catalog is stale in a way that matters. Volatile families get a short TTL.
 */
require_once __DIR__ . '/Embeddings.php';

class AssessmentWarehouse
{
    /**
     * Semantic replay threshold. Deliberately stricter than the agent-merge
     * bar: merging two agents costs a duplicate row, but replaying the wrong
     * assessment shows a person an explanation of a different problem.
     * ponytail: not yet measured on live shape text — see docs/calibration.md.
     * Until it is, it sits high enough that only near-identical shapes replay.
     */
    public const REPLAY_SIM = 0.80;

    /** Fresh threat data invalidates fast; a stable config weakness does not. */
    private const TTL_VOLATILE = 86400 * 3;    // KEV / actively exploited
    private const TTL_STABLE   = 86400 * 30;

    /**
     * Look for a reusable assessment.
     *
     * @return array{payload:array, depth:string, similarity:?float, id:int}|null
     */
    public static function lookup(PDO $pdo, int $tenantId, string $agentKey, string $shapeHash, string $shapeText): ?array
    {
        // --- depth 1: exact shape
        $q = $pdo->prepare(
            "SELECT id, payload, quality FROM assessment_warehouse
              WHERE tenant_id = ? AND shape_hash = ?
                AND (expires_at IS NULL OR expires_at > NOW())
           ORDER BY id DESC LIMIT 1"
        );
        $q->execute([$tenantId, $shapeHash]);
        if ($row = $q->fetch()) {
            $pdo->prepare("UPDATE assessment_warehouse SET hits = hits + 1 WHERE id = ?")
                ->execute([$row['id']]);
            return [
                'payload' => json_decode((string) $row['payload'], true) ?: [],
                'depth' => 'exact', 'similarity' => 1.0, 'id' => (int) $row['id'],
            ];
        }

        // --- depth 2: an equivalent shape for the same agent
        if (!Embeddings::enabled()) {
            return null;
        }
        $rows = $pdo->prepare(
            "SELECT id, payload, embedding FROM assessment_warehouse
              WHERE tenant_id = ? AND agent_key = ? AND embedding IS NOT NULL
                AND (expires_at IS NULL OR expires_at > NOW())
           ORDER BY id DESC LIMIT 200"
        );
        $rows->execute([$tenantId, $agentKey]);
        $candidates = $rows->fetchAll();
        if (!$candidates) {
            return null;
        }

        $mine = Embeddings::embed($pdo, $shapeText, 'retrieval.query');
        if (!$mine) {
            return null;
        }

        $best = null; $bestSim = 0.0;
        foreach ($candidates as $c) {
            $sim = Embeddings::cosine($mine, Embeddings::unpack((string) $c['embedding']));
            if ($sim > $bestSim) { $bestSim = $sim; $best = $c; }
        }
        if (!$best || $bestSim < self::REPLAY_SIM) {
            return null;
        }

        $pdo->prepare("UPDATE assessment_warehouse SET hits = hits + 1 WHERE id = ?")
            ->execute([$best['id']]);
        return [
            'payload' => json_decode((string) $best['payload'], true) ?: [],
            'depth' => 'semantic', 'similarity' => round($bestSim, 4), 'id' => (int) $best['id'],
        ];
    }

    /** Store a freshly generated assessment for later replay. */
    public static function store(
        PDO $pdo, int $tenantId, string $agentKey, string $shapeHash,
        string $shapeText, array $payload, bool $volatile, ?float $quality = null
    ): void {
        $vector = null;
        if (Embeddings::enabled()) {
            $v = Embeddings::embed($pdo, $shapeText);
            if ($v) {
                $vector = Embeddings::pack($v);
            }
        }
        $ttl = $volatile ? self::TTL_VOLATILE : self::TTL_STABLE;

        try {
            $pdo->prepare(
                "INSERT INTO assessment_warehouse
                    (tenant_id, agent_key, shape_hash, shape_text, embedding, payload, quality, expires_at)
                 VALUES (?,?,?,?,?,?,?, DATE_ADD(NOW(), INTERVAL ? SECOND))"
            )->execute([
                $tenantId, $agentKey, $shapeHash, $shapeText, $vector,
                json_encode($payload, JSON_UNESCAPED_UNICODE), $quality, $ttl,
            ]);
        } catch (Throwable $e) {
            // A warehouse write failing must never fail the assessment itself.
            error_log('[AssessmentWarehouse] store failed: ' . $e->getMessage());
        }
    }

    /** Reuse statistics — the number that proves the architecture pays off. */
    public static function stats(PDO $pdo, int $tenantId): array
    {
        $row = $pdo->prepare(
            "SELECT COUNT(*) entries, COALESCE(SUM(hits),0) hits,
                    SUM(embedding IS NOT NULL) with_vector,
                    SUM(expires_at < NOW()) expired
               FROM assessment_warehouse WHERE tenant_id = ?"
        );
        $row->execute([$tenantId]);
        $s = $row->fetch() ?: [];

        return [
            'entries'     => (int) ($s['entries'] ?? 0),
            'replays'     => (int) ($s['hits'] ?? 0),
            'with_vector' => (int) ($s['with_vector'] ?? 0),
            'expired'     => (int) ($s['expired'] ?? 0),
            'semantic_available' => Embeddings::enabled(),
        ];
    }

    /** Drop expired rows. Cheap, and keeps the semantic scan bounded. */
    public static function prune(PDO $pdo): int
    {
        return (int) $pdo->exec("DELETE FROM assessment_warehouse WHERE expires_at < NOW()");
    }
}
