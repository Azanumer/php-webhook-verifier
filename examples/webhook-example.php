<?php

declare(strict_types=1);

require __DIR__ . '/../src/WebhookVerifier.php';

use Azanumer\WebhookVerifier\WebhookVerifier;

// ---------------------------------------------------------------------------
// Simulated incoming webhook: build a payload and sign it the way each
// provider would, then verify it. In production, $payload is the raw
// request body (file_get_contents('php://input')) and the headers come
// from $_SERVER.
// ---------------------------------------------------------------------------

$payload = '{"action":"opened","repository":{"full_name":"Azanumer/demo"}}';
$secret  = 'my-webhook-secret';
$now     = time();

// --- GitHub ---------------------------------------------------------------
$githubHeader = 'sha256=' . hash_hmac('sha256', $payload, $secret);
var_dump(WebhookVerifier::verifyGitHub($payload, $githubHeader, $secret)); // true
var_dump(WebhookVerifier::verifyGitHub($payload, $githubHeader, 'wrong')); // false

// --- Stripe ---------------------------------------------------------------
$stripeSigned = $now . '.' . $payload;
$stripeHeader = 't=' . $now . ',v1=' . hash_hmac('sha256', $stripeSigned, $secret);
var_dump(WebhookVerifier::verifyStripe($payload, $stripeHeader, $secret, 300, $now)); // true

// A signature from 10 minutes ago is a replay — rejected by default.
$old = $now - 600;
$oldHeader = 't=' . $old . ',v1=' . hash_hmac('sha256', $old . '.' . $payload, $secret);
var_dump(WebhookVerifier::verifyStripe($payload, $oldHeader, $secret, 300, $now)); // false

// --- Slack ----------------------------------------------------------------
$slackBase = 'v0:' . $now . ':' . $payload;
$slackHeader = 'v0=' . hash_hmac('sha256', $slackBase, $secret);
var_dump(WebhookVerifier::verifySlack($payload, $slackHeader, (string) $now, $secret, 300, $now)); // true

// --- Generic HMAC ---------------------------------------------------------
var_dump(WebhookVerifier::verifyHmac($payload, hash_hmac('sha256', $payload, $secret), $secret)); // true
var_dump(WebhookVerifier::verifyPrefixedHmac($payload, 'sha256=' . hash_hmac('sha256', $payload, $secret), $secret)); // true
