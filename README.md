# PHP Webhook Verifier

Dependency-free HMAC webhook signature verification — prove an incoming webhook really came from GitHub, Stripe, or Slack before acting on it.

## Usage

```php
require 'src/WebhookVerifier.php';

use Azanumer\WebhookVerifier\WebhookVerifier;

$payload = file_get_contents('php://input');

// GitHub — X-Hub-Signature-256: sha256=<hex>
$ok = WebhookVerifier::verifyGitHub(
    $payload,
    $_SERVER['HTTP_X_HUB_SIGNATURE_256'] ?? '',
    $githubSecret
);

// Stripe — Stripe-Signature: t=<ts>,v1=<hex>
$ok = WebhookVerifier::verifyStripe(
    $payload,
    $_SERVER['HTTP_STRIPE_SIGNATURE'] ?? '',
    $stripeSecret // whsec_...
);

// Slack — X-Slack-Signature: v0=<hex> + X-Slack-Request-Timestamp
$ok = WebhookVerifier::verifySlack(
    $payload,
    $_SERVER['HTTP_X_SLACK_SIGNATURE'] ?? '',
    $_SERVER['HTTP_X_SLACK_REQUEST_TIMESTAMP'] ?? '',
    $slackSecret
);

if (!$ok) {
    http_response_code(401);
    exit('Invalid signature');
}
// ...handle the webhook...
```

## API

| Method | Notes |
|---|---|
| `verifyGitHub($payload, $header, $secret)` | `sha256=<hex>` header |
| `verifyStripe($payload, $header, $secret, $tolerance = 300, $now = null)` | Checks every `v1` entry; rejects timestamps older than `$tolerance` seconds (replay protection). `$now` is injectable for tests |
| `verifySlack($payload, $header, $timestamp, $secret, $tolerance = 300, $now = null)` | Signs `v0:<timestamp>:<payload>`; rejects stale timestamps |
| `verifyHmac($payload, $signature, $secret, $algo = 'sha256')` | Generic raw-hex HMAC check |
| `verifyPrefixedHmac($payload, $header, $secret, $algo = 'sha256', $prefix = null)` | Generic `<prefix>=<hex>` check (prefix defaults to the algorithm name) |

## Security notes

- All comparisons use `hash_equals()` (constant time).
- Stripe/Slack timestamps are checked against a 5-minute tolerance by default — an old, captured signature cannot be replayed later.
- Always verify against the **raw** request body (`php://input`), never a re-encoded `$_POST` — the signature covers the exact bytes.
- Stripe's legacy `v0` entries are ignored; only `v1` signatures are accepted.

## Example

```bash
php examples/webhook-example.php
```

## Requirements

- PHP 7.4+ (no extensions beyond the standard library)

## License

MIT. See [LICENSE](LICENSE).
