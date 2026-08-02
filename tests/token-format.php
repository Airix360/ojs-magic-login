<?php

/**
 * @file tests/token-format.php
 *
 * Standalone tests for the token format used by TokenService.
 * Requires no OJS installation or database — tests the regex pattern and
 * the generation algorithm in isolation.
 *
 * Exit code 0 = all tests passed.
 * Exit code 1 = one or more tests failed.
 */

declare(strict_types=1);

// ── Helpers ───────────────────────────────────────────────────────────────────

$passed = 0;
$failed = 0;

function ok(bool $result, string $label): void
{
    global $passed, $failed;
    if ($result) {
        echo "\033[32m  PASS\033[0m  $label\n";
        $passed++;
    } else {
        echo "\033[31m  FAIL\033[0m  $label\n";
        $failed++;
    }
}

// ── Constants mirrored from TokenService / MagicLoginHandler ─────────────────

const TOKEN_PATTERN  = '/^[0-9a-f]{32}\.[A-Za-z0-9\-_]{43}$/';
const TOKEN_MAX_LEN  = 200;
const SELECTOR_LEN   = 32;   // hex chars  = 16 raw bytes
const VERIFIER_LEN   = 43;   // base64url  = 32 raw bytes stripped of padding

// ── Generate a real token the same way TokenService does ─────────────────────

function generateToken(): string
{
    $selector = bin2hex(random_bytes(16));
    $verifier = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
    return $selector . '.' . $verifier;
}

// ── Test suite ────────────────────────────────────────────────────────────────

echo "\nToken format tests\n";
echo str_repeat('─', 50) . "\n";

// Structure
echo "\n[Structure]\n";
$token = generateToken();
[$sel, $ver] = explode('.', $token, 2);
ok(strlen($sel) === SELECTOR_LEN,      "Selector is exactly " . SELECTOR_LEN . " chars");
ok(strlen($ver) === VERIFIER_LEN,      "Verifier is exactly " . VERIFIER_LEN . " chars");
ok(strlen($token) === 76,              "Full token is exactly 76 chars (32 + 1 + 43)");
ok(preg_match(TOKEN_PATTERN, $token) === 1, "Generated token matches TOKEN_PATTERN");

// Pattern — valid inputs
echo "\n[Pattern: valid tokens]\n";
$validTokens = [
    '80718d8598392731911fb8187c4d842c.R7JWanoaVaN7aLYPTt4RcPNqVb91cswwciZFNEwv8-Q',
    'aabbccddeeff00112233445566778899.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
    '00000000000000000000000000000000.BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB',
    'ffffffffffffffffffffffffffffffff.abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG',
    '1234567890abcdef1234567890abcdef.A-B_C-D_E-F_G-H_I-J_K-L_M-N_O-P_Q-R_S-T_UVW',
];
foreach ($validTokens as $t) {
    ok(preg_match(TOKEN_PATTERN, $t) === 1, "Accepts valid token (…" . substr($t, -8) . ")");
}

// Pattern — rejected inputs
echo "\n[Pattern: invalid / malicious inputs]\n";
$invalid = [
    ''                                              => 'Empty string',
    'tooshort'                                      => 'Too short',
    str_repeat('a', 200)                            => 'Exceeds MAX_LEN',
    '80718d8598392731911fb8187c4d842c'              => 'Selector only (no dot, no verifier)',
    '80718d8598392731911fb8187c4d842c.'             => 'Trailing dot, empty verifier',
    '.R7JWanoaVaN7aLYPTt4RcPNqVb91cswwciZFNEwv8-Q' => 'Leading dot, empty selector',
    // Uppercase hex in selector (must be lowercase)
    '80718D8598392731911FB8187C4D842C.R7JWanoaVaN7aLYPTt4RcPNqVb91cswwciZFNEwv8-Q' => 'Uppercase hex in selector',
    // Wrong verifier length (42 chars instead of 43)
    '80718d8598392731911fb8187c4d842c.R7JWanoaVaN7aLYPTt4RcPNqVb91cswwciZFNEwv8-'  => 'Verifier too short (42)',
    // Wrong verifier length (44 chars instead of 43)
    '80718d8598392731911fb8187c4d842c.R7JWanoaVaN7aLYPTt4RcPNqVb91cswwciZFNEwv8-QQ' => 'Verifier too long (44)',
    // Path traversal
    '../../../etc/passwd'                           => 'Path traversal attempt',
    // Base64 padding chars (must be stripped)
    '80718d8598392731911fb8187c4d842c.R7JWanoaVaN7aLYPTt4RcPNqVb91cswwciZFNEwv8=='  => 'Base64 padding (=) not allowed',
    // SQL injection fragment
    "' OR '1'='1"                                  => 'SQL injection fragment',
    // Null byte
    "80718d8598392731911fb8187c4d842c\x00.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" => 'Null byte in token',
];
foreach ($invalid as $input => $label) {
    ok(preg_match(TOKEN_PATTERN, $input) !== 1, "Rejects: $label");
}

// Length gate (mirrors MagicLoginHandler::sanitizeToken)
echo "\n[Length gate]\n";
ok(strlen(generateToken()) <= TOKEN_MAX_LEN, "Generated token is within MAX_LEN ($TOKEN_MAX_LEN)");
ok(strlen(str_repeat('a', TOKEN_MAX_LEN + 1)) > TOKEN_MAX_LEN, "Oversized string exceeds MAX_LEN (sanity)");

// Entropy — selectors generated in 10 iterations must all be unique
echo "\n[Entropy]\n";
$selectors = [];
for ($i = 0; $i < 10; $i++) {
    $t = generateToken();
    $selectors[] = explode('.', $t)[0];
}
ok(count(array_unique($selectors)) === 10, "10 consecutive selectors are all unique");

// Hash — stored hash differs from raw verifier
echo "\n[Hash storage]\n";
$t = generateToken();
[, $ver] = explode('.', $t, 2);
$hash = hash('sha256', $ver);
ok($hash !== $ver,          "sha256(verifier) !== verifier");
ok(strlen($hash) === 64,    "sha256 output is 64 hex chars");
ok(preg_match('/^[0-9a-f]{64}$/', $hash) === 1, "sha256 output is lowercase hex");
ok(hash_equals($hash, hash('sha256', $ver)), "hash_equals returns true for same verifier");
ok(!hash_equals($hash, hash('sha256', 'wrong')), "hash_equals returns false for wrong verifier");

// ── CSRF: login-CSRF fix (source-level regression check) ─────────────────────
//
// This repo's runtime classes (MagicLoginHandler, TokenService) extend/use
// OJS/PKP framework classes that are not available outside a full OJS
// install, so — matching this file's existing "no OJS bootstrap required"
// style — these checks assert on the *source* rather than instantiating the
// handler. They exist to catch a regression of the login-CSRF bypass fix
// (audit HIGH finding: CSRF was skipped whenever Validation::isLoggedIn()
// was true) and the token-consumption-atomicity fix (audit Medium finding).

echo "\n[CSRF: login-CSRF fix]\n";
$handlerSrc = file_get_contents(__DIR__ . '/../pages/MagicLoginHandler.php');

ok(
    strpos($handlerSrc, 'isLoggedIn() ? true :') === false,
    'validateCsrf() no longer short-circuits CSRF when the requester is already logged in'
);
ok(
    (bool) preg_match(
        '/private function validateCsrf\(\$request\): bool\s*\{\s*return \$request->checkCSRF\(\);\s*\}/',
        $handlerSrc
    ),
    'validateCsrf() unconditionally delegates to $request->checkCSRF()'
);
ok(
    (bool) preg_match('/function send\(.*?\).*?validateCsrf\(\$request\)/s', $handlerSrc),
    'send() still calls validateCsrf() before doing any work'
);
ok(
    (bool) preg_match('/function login\(.*?\).*?validateCsrf\(\$request\)/s', $handlerSrc),
    'login() still calls validateCsrf() before doing any work'
);

// ── Atomicity: verify+consume fix (source-level regression check) ────────────

echo "\n[Atomicity: verify+consume fix]\n";
$tokenServiceSrc = file_get_contents(__DIR__ . '/../classes/TokenService.php');

ok(
    strpos($tokenServiceSrc, 'function verifyAndConsume(') !== false,
    'TokenService exposes an atomic verifyAndConsume() method'
);
ok(
    (bool) preg_match(
        '/function verifyAndConsume\(.*?\{.*?DB::transaction\(/s',
        $tokenServiceSrc
    ),
    'verifyAndConsume() runs inside DB::transaction()'
);
ok(
    strpos($tokenServiceSrc, 'lockForUpdate()') !== false,
    'verifyAndConsume() locks the selector row with lockForUpdate() before checking it'
);
ok(
    (bool) preg_match('/\$deleted\s*===\s*0/', $tokenServiceSrc),
    'verifyAndConsume() checks the consuming delete\'s affected-row count and fails closed on 0'
);
ok(
    (bool) preg_match('/where\(\'setting_value\',\s*\$selector\)\s*->\s*delete\(\)/s', $tokenServiceSrc),
    'the consuming delete is scoped to the specific selector, not just the user ID'
);

// login() must call the atomic method instead of separate verify()+consume() calls.
ok(
    (bool) preg_match('/function login\(.*?verifyAndConsume\(\$token\)/s', $handlerSrc),
    'login() calls the atomic verifyAndConsume() instead of separate verify()+consume()'
);
ok(
    !(bool) preg_match('/function login\(.*?->consume\(\$user\)/s', $handlerSrc),
    'login() no longer calls the non-atomic consume() after a separate verify()'
);

// ── Recent-activity log: source-level regression check ───────────────────────
//
// New in this branch: an admin-facing "recent activity" panel in Settings,
// backed by a capped JSON list written by MagicLoginHandler::recordAttempt().
// It is explicitly a best-effort visibility log, not a security control, so
// these checks confirm (a) it exists and is wired to every event, (b) it is
// capped so the stored setting cannot grow unbounded, and (c) a write failure
// there cannot break the login flow (caught, not rethrown).

echo "\n[Recent activity log]\n";
$pluginSrc = file_get_contents(__DIR__ . '/../MagicLoginPlugin.php');
$formSrc   = file_get_contents(__DIR__ . '/../MagicLoginSettingsForm.php');

ok(
    strpos($pluginSrc, 'RECENT_ATTEMPTS_SETTING') !== false
        && strpos($pluginSrc, 'RECENT_ATTEMPTS_MAX') !== false,
    'MagicLoginPlugin defines the recent-attempts setting name and cap'
);
ok(
    strpos($handlerSrc, 'private function recordAttempt(') !== false,
    'MagicLoginHandler defines recordAttempt()'
);
ok(
    (bool) preg_match('/function recordAttempt\(.*?\{\s*try\s*\{/s', $handlerSrc),
    'recordAttempt() wraps its work in try/catch so a logging failure cannot break login'
);
ok(
    strpos($handlerSrc, 'array_slice($events, 0, MagicLoginPlugin::RECENT_ATTEMPTS_MAX)') !== false,
    'recordAttempt() caps the stored event list to RECENT_ATTEMPTS_MAX'
);

// Every event already written to error_log should also call recordAttempt(),
// so the admin panel and the error_log stream never drift apart.
$expectedEvents = [
    'SEND_RATELIMIT',
    'LINK_SENT',
    'LINK_SEND_FAILED',
    'LOGIN_RATELIMIT',
    'LOGIN_FAIL',
    'LOGIN_SUCCESS',
];
foreach ($expectedEvents as $eventCode) {
    ok(
        (bool) preg_match('/recordAttempt\([^)]*\'' . preg_quote($eventCode, '/') . '\'/', $handlerSrc),
        "recordAttempt() is called for {$eventCode}"
    );
}

ok(
    strpos($formSrc, 'buildRecentAttemptsView') !== false,
    'MagicLoginSettingsForm builds a read-only recent-attempts view for the template'
);
ok(
    strpos($formSrc, "setData('recentAttempts'") !== false,
    'MagicLoginSettingsForm exposes recentAttempts to settings.tpl'
);

$templateSrc = file_get_contents(__DIR__ . '/../templates/settings.tpl');
ok(
    strpos($templateSrc, '$recentAttempts') !== false,
    'settings.tpl renders $recentAttempts'
);

// ── Summary ───────────────────────────────────────────────────────────────────

echo "\n" . str_repeat('─', 50) . "\n";
$total = $passed + $failed;
if ($failed === 0) {
    echo "\033[32mAll $total tests passed.\033[0m\n\n";
    exit(0);
} else {
    echo "\033[31m$failed of $total tests FAILED.\033[0m\n\n";
    exit(1);
}
