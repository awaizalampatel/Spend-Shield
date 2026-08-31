<?php
/**
 * Embeddings — Jina v3, with a database cache.
 *
 * An embedding turns text into a vector where similar MEANING lands in a similar
 * place. That is what lets the system ask "have I already assessed something
 * that means the same thing?" — a question exact text matching cannot answer,
 * because "RDP exposed on plant-jump-01" and "Remote Desktop reachable from the
 * internet on vc-mgmt-02" share almost no words and are the same problem.
 *
 * Everything is cached by sha1(model + task + text). Agent descriptions barely
 * change and finding shapes repeat constantly, so after warmup this is a table
 * lookup and costs nothing. Vectors are stored as packed float32, not JSON — a
 * 1024-dim vector is 4 KB packed and about 20 KB as text.
 *
 * Degrades to null on any failure. Every caller treats "no embedding" as "skip
 * the semantic step", never as an error — the product must keep working when a
 * third-party API is down.
 */
class Embeddings
{
    public const MODEL = 'jina-embeddings-v3';
    public const DIMS  = 1024;
    private const ENDPOINT = 'https://api.jina.ai/v1/embeddings';
    private const BATCH = 64;

    private static ?bool $enabled = null;

    public static function enabled(): bool
    {
        if (self::$enabled === null) {
            self::$enabled = defined('JINA_API_KEY') && JINA_API_KEY !== '';
        }
        return self::$enabled;
    }

    /**
     * Embed many strings at once. Returns [text => vector|null], preserving
     * input order. Cached entries never hit the network.
     *
     * @param string[] $texts
     * @param string   $task  retrieval.passage for stored text, retrieval.query for a lookup
     * @return array<int, array<int,float>|null>
     */
    public static function embedMany(PDO $pdo, array $texts, string $task = 'retrieval.passage'): array
    {
        $out = array_fill(0, count($texts), null);
        if (!self::enabled() || !$texts) {
            return $out;
        }

        // --- cache pass
        $need = [];   // hash => list of positions
        $hashes = [];
        foreach ($texts as $i => $t) {
            $t = trim((string) $t);
            if ($t === '') {
                continue;
            }
            $h = self::hash($t, $task);
            $hashes[$i] = $h;
            $need[$h][] = $i;
        }
        if (!$need) {
            return $out;
        }

        $in = implode(',', array_fill(0, count($need), '?'));
        $q = $pdo->prepare("SELECT hash, vector FROM embeddings WHERE hash IN ($in)");
        $q->execute(array_keys($need));
        $missing = $need;
        foreach ($q as $row) {
            $vec = self::unpack((string) $row['vector']);
            foreach ($need[$row['hash']] as $pos) {
                $out[$pos] = $vec;
            }
            unset($missing[$row['hash']]);
        }
        if (!$missing) {
            return $out;
        }

        // --- fetch the rest
        $toFetch = [];
        foreach ($missing as $h => $positions) {
            $toFetch[$h] = trim((string) $texts[$positions[0]]);
        }

        $ins = $pdo->prepare(
            "INSERT INTO embeddings (hash, model, task, dims, vector) VALUES (?,?,?,?,?)
             ON DUPLICATE KEY UPDATE hash = hash"
        );

        foreach (array_chunk($toFetch, self::BATCH, true) as $chunk) {
            $vectors = self::call(array_values($chunk), $task);
            if ($vectors === null) {
                continue;                        // API failed — leave those null
            }
            $i = 0;
            foreach ($chunk as $h => $text) {
                $vec = $vectors[$i++] ?? null;
                if (!is_array($vec)) {
                    continue;
                }
                foreach ($need[$h] as $pos) {
                    $out[$pos] = $vec;
                }
                try {
                    $ins->execute([$h, self::MODEL, $task, count($vec), self::pack($vec)]);
                } catch (Throwable $e) {
                    // A cache write failing must never fail the caller.
                    error_log('[Embeddings] cache write failed: ' . $e->getMessage());
                }
            }
        }

        return $out;
    }

    /** One string. */
    public static function embed(PDO $pdo, string $text, string $task = 'retrieval.passage'): ?array
    {
        return self::embedMany($pdo, [$text], $task)[0] ?? null;
    }

    /**
     * Cosine similarity. Both vectors must be the same length; returns 0.0 when
     * either is missing, so a failed embedding reads as "not similar" rather
     * than accidentally matching everything.
     */
    public static function cosine(?array $a, ?array $b): float
    {
        if (!$a || !$b || count($a) !== count($b)) {
            return 0.0;
        }
        $dot = 0.0; $na = 0.0; $nb = 0.0;
        foreach ($a as $i => $x) {
            $y = $b[$i];
            $dot += $x * $y;
            $na  += $x * $x;
            $nb  += $y * $y;
        }
        if ($na <= 0 || $nb <= 0) {
            return 0.0;
        }
        return $dot / sqrt($na * $nb);
    }

    // ------------------------------------------------------------- internals

    private static function hash(string $text, string $task): string
    {
        return sha1(self::MODEL . '|' . $task . '|' . $text);
    }

    /** float32 little-endian — 4 bytes per dimension instead of ~20 as text. */
    public static function pack(array $vec): string
    {
        return pack('g*', ...$vec);
    }

    public static function unpack(string $blob): array
    {
        $v = unpack('g*', $blob);
        return $v ? array_values($v) : [];
    }

    /** @return array<int,array<int,float>>|null */
    private static function call(array $texts, string $task): ?array
    {
        $ch = curl_init(self::ENDPOINT);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_POST           => true,
            CURLOPT_TIMEOUT        => 30,
            CURLOPT_CONNECTTIMEOUT => 10,
            CURLOPT_HTTPHEADER     => [
                'Content-Type: application/json',
                'Authorization: Bearer ' . JINA_API_KEY,
            ],
            CURLOPT_POSTFIELDS => json_encode([
                'model' => self::MODEL,
                'task'  => $task,
                'input' => array_values($texts),
            ]),
        ]);
        $body = curl_exec($ch);
        $code = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $err  = curl_error($ch);
        curl_close($ch);

        if ($body === false || $code !== 200) {
            error_log('[Embeddings] HTTP ' . $code . ' ' . $err . ' ' . substr((string) $body, 0, 200));
            return null;
        }
        $j = json_decode((string) $body, true);
        if (!isset($j['data']) || !is_array($j['data'])) {
            return null;
        }
        return array_column($j['data'], 'embedding');
    }
}
