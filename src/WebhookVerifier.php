<?php

declare(strict_types=1);

namespace Azanumer\WebhookVerifier;

/**
 * Dependency-free HMAC webhook signature verification.
 *
 * Covers the three most common providers plus a generic HMAC check:
 *
 *  - GitHub:   X-Hub-Signature-256: sha256=<hex>
 *  - Stripe:   Stripe-Signature: t=<ts>,v1=<hex>[,v1=<hex>...]
 *  - Slack:    X-Slack-Signature: v0=<hex> with X-Slack-Request-Timestamp
 *
 * Every comparison uses hash_equals() (constant time). Stripe and Slack
 * signatures are rejected when the timestamp is older than the tolerance,
 * which blocks replay attacks.
 */
class WebhookVerifier
{
    /**
     * Verify a GitHub webhook signature (X-Hub-Signature-256).
     *
     * @param string $payload Raw request body.
     * @param string $signatureHeader Value of the X-Hub-Signature-256 header.
     * @param string $secret Webhook secret.
     */
    public static function verifyGitHub(string $payload, string $signatureHeader, string $secret): bool
    {
        return self::verifyPrefixedHmac($payload, $signatureHeader, $secret, 'sha256');
    }

    /**
     * Verify a Stripe webhook signature (Stripe-Signature header).
     *
     * @param string $payload Raw request body.
     * @param string $signatureHeader Value of the Stripe-Signature header.
     * @param string $secret Webhook signing secret (whsec_...).
     * @param int $toleranceSeconds Maximum age of the signature timestamp.
     * @param int|null $now Current Unix time (injectable for tests).
     */
    public static function verifyStripe(
        string $payload,
        string $signatureHeader,
        string $secret,
        int $toleranceSeconds = 300,
        ?int $now = null
    ): bool {
        $now = $now ?? time();
        $parts = self::parseStripeHeader($signatureHeader);
        if (null === $parts) {
            return false;
        }
        [$timestamp, $signatures] = $parts;
        if (abs($now - $timestamp) > $toleranceSeconds) {
            return false;
        }
        $signedPayload = $timestamp . '.' . $payload;
        $expected = hash_hmac('sha256', $signedPayload, $secret);
        foreach ($signatures as $signature) {
            if (hash_equals($expected, $signature)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Verify a Slack request signature (X-Slack-Signature header).
     *
     * @param string $payload Raw request body.
     * @param string $signatureHeader Value of the X-Slack-Signature header.
     * @param string $timestamp Value of the X-Slack-Request-Timestamp header.
     * @param string $secret Slack signing secret.
     * @param int $toleranceSeconds Maximum age of the request timestamp.
     * @param int|null $now Current Unix time (injectable for tests).
     */
    public static function verifySlack(
        string $payload,
        string $signatureHeader,
        string $timestamp,
        string $secret,
        int $toleranceSeconds = 300,
        ?int $now = null
    ): bool {
        $now = $now ?? time();
        if (!ctype_digit($timestamp)) {
            return false;
        }
        if (abs($now - (int) $timestamp) > $toleranceSeconds) {
            return false;
        }
        $baseString = 'v0:' . $timestamp . ':' . $payload;
        return self::verifyPrefixedHmac($baseString, $signatureHeader, $secret, 'sha256', 'v0');
    }

    /**
     * Generic HMAC verification against a raw hex signature.
     *
     * @param string $payload Data that was signed.
     * @param string $signature Hex-encoded signature to check.
     * @param string $secret Shared secret.
     * @param string $algo hash_hmac() algorithm, e.g. sha256.
     */
    public static function verifyHmac(string $payload, string $signature, string $secret, string $algo = 'sha256'): bool
    {
        if ('' === $signature || '' === $secret) {
            return false;
        }
        if (!in_array($algo, hash_hmac_algos(), true)) {
            return false;
        }
        $expected = hash_hmac($algo, $payload, $secret);
        return hash_equals($expected, strtolower(trim($signature)));
    }

    /**
     * Verify a "<prefix>=<hex>" style signature, e.g. "sha256=abc..." or "v0=abc...".
     *
     * @param string $payload Data that was signed.
     * @param string $signatureHeader Full header value.
     * @param string $secret Shared secret.
     * @param string $algo hash_hmac() algorithm.
     * @param string|null $expectedPrefix Required prefix when given; when null,
     *                                    the prefix must equal $algo.
     */
    public static function verifyPrefixedHmac(
        string $payload,
        string $signatureHeader,
        string $secret,
        string $algo = 'sha256',
        ?string $expectedPrefix = null
    ): bool {
        $prefix = $expectedPrefix ?? $algo;
        $needle = $prefix . '=';
        if (0 !== strpos($signatureHeader, $needle)) {
            return false;
        }
        $signature = substr($signatureHeader, strlen($needle));
        return self::verifyHmac($payload, $signature, $secret, $algo);
    }

    /**
     * Parse a Stripe-Signature header into [timestamp, v1 signatures].
     *
     * @return array{int, string[]}|null Null when the header is malformed.
     */
    private static function parseStripeHeader(string $header): ?array
    {
        $timestamp = null;
        $signatures = [];
        foreach (explode(',', $header) as $part) {
            $part = trim($part);
            if ('' === $part) {
                continue;
            }
            $kv = explode('=', $part, 2);
            if (2 !== count($kv)) {
                continue;
            }
            [$key, $value] = $kv;
            if ('t' === $key && ctype_digit($value)) {
                $timestamp = (int) $value;
            } elseif ('v1' === $key && '' !== $value) {
                $signatures[] = $value;
            }
            // v0 entries (older scheme) are ignored on purpose.
        }
        if (null === $timestamp || [] === $signatures) {
            return null;
        }
        return [$timestamp, $signatures];
    }
}
