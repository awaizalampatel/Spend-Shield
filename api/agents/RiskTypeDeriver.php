<?php
/**
 * RiskTypeDeriver — lets a finding name its own risk family.
 *
 * There is no hardcoded list of risk types. "Internet-facing RDP",
 * "Cloud storage exposure", "Legacy OT protocol" are names the system has never
 * seen before, produced from the findings that arrive. That is what makes the
 * agent roster a picture of THIS estate rather than a fixed taxonomy.
 *
 * Cost control: the naming is one cheap model call, cached by the family key —
 * the structural signature with hostnames and CVE ids already stripped out. So
 * 500 Exchange findings pay for one derivation, and every later one is a table
 * lookup. On a warm database this class makes no network calls at all.
 *
 * Degrades to a deterministic fallback name if the model is unavailable, so a
 * missing API key costs you a nice name, not the feature.
 */
require_once __DIR__ . '/OpenRouter.php';
require_once __DIR__ . '/RiskShape.php';

class RiskTypeDeriver
{
    /**
     * @return array{slug:string,name:string,description:string,lane:string,derived:bool}
     */
    public static function derive(PDO $pdo, array $vuln, array $asset): array
    {
        $family = RiskShape::familyKey($vuln, $asset);
        $sig = sha1($family);
        // The technology family, straight off the key. Carried on every result
        // because AgentRegistry refuses to merge across different subjects.
        $subject = explode("|", $family)[1] ?? "";

        $q = $pdo->prepare("SELECT slug, name, description, lane FROM risk_type_cache WHERE signature = ?");
        $q->execute([$sig]);
        if ($row = $q->fetch()) {
            return [
                'slug' => $row['slug'], 'name' => $row['name'],
                'description' => (string) $row['description'], 'lane' => (string) $row['lane'],
                'subject' => $subject, 'derived' => false,
            ];
        }

        $result = self::ask($vuln, $asset, $family) ?? self::fallback($vuln, $asset, $family);

        try {
            $pdo->prepare(
                "INSERT INTO risk_type_cache (signature, slug, name, description, lane)
                 VALUES (?,?,?,?,?)
                 ON DUPLICATE KEY UPDATE name = VALUES(name)"
            )->execute([$sig, $result['slug'], $result['name'], $result['description'], $result['lane']]);
        } catch (Throwable $e) {
            error_log('[RiskTypeDeriver] cache write failed: ' . $e->getMessage());
        }

        return $result + ['subject' => $subject, 'derived' => true];
    }

    /** One cheap call. Returns null on any failure — the caller falls back. */
    private static function ask(array $vuln, array $asset, string $family): ?array
    {
        if (!OpenRouter::enabled()) {
            return null;
        }

        // DELIBERATELY WITHHOLDING THE SPECIFIC WEAKNESS.
        //
        // The first version passed the finding's title, and the model did the
        // obvious thing with it: the family vuln|windows|internal was named
        // "WSUS Deserialization Vulnerability" because a WSUS finding happened
        // to arrive first — and then every Windows internal vulnerability in the
        // estate, Print Spooler included, was assessed by an agent named after
        // something else entirely.
        //
        // An agent covers a family, so the namer may only see the family. Show
        // it the product, the reachability and the asset class; never the CVE,
        // the hostname, or the specific weakness that triggered creation.
        [$kind, $subject] = array_pad(explode('|', $family), 2, '');
        $context = 'Kind: ' . ($kind === 'config' ? 'configuration weakness' : 'software vulnerability') . "\n"
            . 'Technology family: ' . str_replace(['cfg.', '_'], ['', ' '], $subject) . "\n"
            . 'Asset class: ' . (string) ($asset['asset_class'] ?? 'system') . "\n"
            . 'Reachable from: ' . RiskShape::exposure($asset) . "\n"
            . 'This family will cover EVERY finding of this kind across the estate, '
            . 'on many different hosts and many different CVEs.';

        $res = OpenRouter::chat(OpenRouter::CHEAP, [
            ['role' => 'system', 'content' =>
                'You name reusable RISK FAMILIES for a cyber risk platform. A family covers every '
                . 'finding of the same kind across an estate, so the name must be general — name the '
                . 'CLASS of problem, never the specific host, CVE or vendor version. '
                . "Reply with exactly three lines and nothing else:\n"
                . "SLUG: lower_snake_case, 2-4 words\n"
                . "NAME: Title Case, 2-4 words\n"
                . "DESC: one sentence saying what this family covers and why it matters"],
            ['role' => 'user', 'content' => $context],
        ], ['max_tokens' => 120, 'temperature' => 0], 'derive_risk_type');

        if ($res['error'] !== null || $res['content'] === '') {
            return null;
        }

        $slug = $name = $desc = '';
        foreach (explode("\n", $res['content']) as $line) {
            if (preg_match('/^\s*SLUG:\s*(.+)$/i', $line, $m)) { $slug = trim($m[1]); }
            if (preg_match('/^\s*NAME:\s*(.+)$/i', $line, $m)) { $name = trim($m[1]); }
            if (preg_match('/^\s*DESC:\s*(.+)$/i', $line, $m)) { $desc = trim($m[1]); }
        }

        $slug = strtolower(preg_replace('/[^a-z0-9]+/i', '_', $slug));
        $slug = trim($slug, '_');
        if ($slug === '' || $name === '') {
            return null;
        }

        return [
            'slug' => mb_substr($slug, 0, 60),
            'name' => mb_substr($name, 0, 120),
            'description' => mb_substr($desc, 0, 400),
            'lane' => self::lane($vuln, $asset),
        ];
    }

    /** Deterministic naming when the model is unavailable. Never pretty, always works. */
    private static function fallback(array $vuln, array $asset, string $family): array
    {
        [$kind, $subject, $exposure] = array_pad(explode('|', $family), 3, '');
        $subject = str_replace(['cfg.', '_'], ['', ' '], $subject);
        $slug = strtolower(preg_replace('/[^a-z0-9]+/i', '_', $subject . '_' . $exposure));
        return [
            'slug' => trim($slug, '_'),
            'name' => ucwords($subject) . ' (' . $exposure . ')',
            'description' => RiskShape::describe($vuln, $asset),
            'lane' => self::lane($vuln, $asset),
        ];
    }

    /**
     * Which lane the family sits in — this decides the model an agent gets when
     * it is created, so cheap families never land on an expensive model.
     */
    private static function lane(array $vuln, array $asset): string
    {
        if (($vuln['source'] ?? '') === 'config') {
            return 'configuration';
        }
        if (RiskShape::exposure($asset) === 'ot') {
            return 'operational_technology';
        }
        if (!empty($vuln['kev_listed'])) {
            return 'exploited';
        }
        return 'vulnerability';
    }
}
