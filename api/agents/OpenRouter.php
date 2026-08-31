<?php
/**
 * OpenRouter — one small client, and a meter.
 *
 * Every call records what it cost, because "the AI features cost about X" is
 * not an answer anyone can act on. The /agents page reports real spend by
 * purpose, and a reused assessment reads $0.00 because it genuinely made no call.
 */
class OpenRouter
{
    private const ENDPOINT = 'https://openrouter.ai/api/v1/chat/completions';

    /** Cheapest model that can follow a short instruction reliably. */
    public const CHEAP  = 'google/gemini-2.5-flash-lite';
    public const STANDARD = 'google/gemini-2.5-flash';

    /** @var array<int,array{model:string,purpose:string,cost:float,ms:int}> */
    private static array $calls = [];

    public static function enabled(): bool
    {
        return defined('OPENROUTER_API_KEY') && OPENROUTER_API_KEY !== '';
    }

    /**
     * @return array{content:string,cost:float,error:?string}
     */
    public static function chat(string $model, array $messages, array $opts = [], string $purpose = 'general'): array
    {
        if (!self::enabled()) {
            return ['content' => '', 'cost' => 0.0, 'error' => 'no API key configured'];
        }
        $t0 = microtime(true);

        $ch = curl_init(self::ENDPOINT);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_POST           => true,
            CURLOPT_TIMEOUT        => (int) ($opts['timeout'] ?? 40),
            CURLOPT_CONNECTTIMEOUT => 10,
            CURLOPT_HTTPHEADER     => [
                'Content-Type: application/json',
                'Authorization: Bearer ' . OPENROUTER_API_KEY,
                'X-Title: SpendShield',
            ],
            CURLOPT_POSTFIELDS => json_encode([
                'model'       => $model,
                'messages'    => $messages,
                'max_tokens'  => (int) ($opts['max_tokens'] ?? 300),
                'temperature' => (float) ($opts['temperature'] ?? 0),
            ]),
        ]);
        $body = curl_exec($ch);
        $code = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $err  = curl_error($ch);
        curl_close($ch);
        $ms = (int) ((microtime(true) - $t0) * 1000);

        if ($body === false || $code !== 200) {
            error_log('[OpenRouter] HTTP ' . $code . ' ' . $err . ' ' . substr((string) $body, 0, 200));
            return ['content' => '', 'cost' => 0.0, 'error' => 'HTTP ' . $code];
        }

        $j = json_decode((string) $body, true);
        $content = (string) ($j['choices'][0]['message']['content'] ?? '');
        // OpenRouter returns the authoritative cost per request — use it rather
        // than a price table that drifts out of date.
        $cost = (float) ($j['usage']['cost'] ?? 0);

        self::$calls[] = ['model' => $model, 'purpose' => $purpose, 'cost' => $cost, 'ms' => $ms];

        return ['content' => trim($content), 'cost' => $cost, 'error' => null];
    }

    public static function reset(): void
    {
        self::$calls = [];
    }

    public static function totalCost(): float
    {
        return array_sum(array_column(self::$calls, 'cost'));
    }

    public static function calls(): array
    {
        return self::$calls;
    }

    /** Cost grouped by what the call was for. */
    public static function summary(): array
    {
        $out = [];
        foreach (self::$calls as $c) {
            $out[$c['purpose']]['calls'] = ($out[$c['purpose']]['calls'] ?? 0) + 1;
            $out[$c['purpose']]['cost']  = ($out[$c['purpose']]['cost'] ?? 0) + $c['cost'];
        }
        return $out;
    }
}
