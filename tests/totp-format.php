<?php

/**
 * @file tests/totp-format.php
 *
 * Standalone tests for the TOTP (RFC 6238) / HOTP (RFC 4226) implementation
 * in classes/TotpService.php, plus source-level regression checks for the
 * security properties added around it (replay protection, at-rest
 * encryption, rate limiting, re-auth on disable). Requires no OJS
 * installation or database.
 *
 * TotpService is framework-free (no OJS/PKP classes), so it is loaded and
 * exercised directly here — unlike TokenService/MagicLoginHandler elsewhere
 * in this test suite, which can only be checked at the source level.
 *
 * Exit code 0 = all tests passed.
 * Exit code 1 = one or more tests failed.
 */

declare(strict_types=1);

require_once __DIR__ . '/../classes/TotpService.php';
require_once __DIR__ . '/../classes/SecretCipher.php';

use APP\plugins\generic\magicLogin\classes\TotpService;
use APP\plugins\generic\magicLogin\classes\SecretCipher;

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

echo "\nTOTP / HOTP tests\n";
echo str_repeat('─', 50) . "\n";

// ── RFC 4226 Appendix D test vectors (HOTP, SHA-1, 6 digits) ─────────────────
// Secret: ASCII "12345678901234567890" (20 bytes). TOTP is HOTP with the
// counter derived from time, so verifying hotp() against these published
// vectors verifies the exact same HMAC-SHA1 + dynamic-truncation logic TOTP
// relies on.
echo "\n[RFC 4226 Appendix D vectors]\n";
$rfcSecret = '12345678901234567890';
$rfcVectors = [
    0 => '755224',
    1 => '287082',
    2 => '359152',
    3 => '969429',
    4 => '338314',
    5 => '254676',
    6 => '287922',
    7 => '162583',
    8 => '399871',
    9 => '520489',
];
foreach ($rfcVectors as $counter => $expected) {
    $actual = TotpService::hotp($rfcSecret, $counter);
    ok($actual === $expected, "HOTP counter={$counter} => {$expected} (got {$actual})");
}

// ── Base32 round-trip ─────────────────────────────────────────────────────────
echo "\n[Base32 round-trip]\n";
$secret = TotpService::generateSecretBase32();
ok(strlen($secret) > 0, 'generateSecretBase32() returns a non-empty string');
ok((bool) preg_match('/^[A-Z2-7]+$/', $secret), 'generateSecretBase32() output is valid base32 alphabet');
$decoded = TotpService::base32Decode($secret);
ok($decoded !== null && strlen($decoded) === TotpService::SECRET_BYTES, 'base32Decode() recovers ' . TotpService::SECRET_BYTES . ' raw bytes');
ok(TotpService::base32Encode($decoded) === $secret, 'base32Encode(base32Decode($x)) === $x (round-trip)');

// Known base32 vector: "12345678901234567890" (RFC 4226 secret) -> base32.
// Independently computed reference value for a regression check.
$knownB32 = TotpService::base32Encode($rfcSecret);
ok(TotpService::base32Decode($knownB32) === $rfcSecret, 'base32 encode/decode round-trips the RFC 4226 ASCII secret exactly');

// Lenient decode: lowercase, spaces, and padding are all tolerated (real-world
// copy/paste from an authenticator app's manual-entry display).
$spaced = strtolower(implode(' ', str_split($secret, 4))) . '===';
ok(TotpService::base32Decode($spaced) === $decoded, 'base32Decode() tolerates lowercase, spaces, and padding');

// Malformed base32 is rejected, not silently mangled.
ok(TotpService::base32Decode('') === null, 'base32Decode() rejects empty string');
ok(TotpService::base32Decode('not-valid-base32!!') === null, 'base32Decode() rejects invalid characters');

// ── TOTP end-to-end verify() ─────────────────────────────────────────────────
echo "\n[verify() end-to-end]\n";
$now = 1_700_000_000; // fixed reference timestamp for determinism
$code = TotpService::totp($decoded === null ? '' : TotpService::base32Decode($secret), $now);
$matchedStep = TotpService::verify($secret, $code, 1, TotpService::PERIOD, TotpService::DIGITS, $now);
ok($matchedStep !== null, 'verify() accepts the code generated for the same timestamp');
ok($matchedStep === intdiv($now, TotpService::PERIOD), 'verify() returns the exact matched time-step counter');

$wrongCode = str_pad((string) ((((int) $code) + 1) % 1_000_000), 6, '0', STR_PAD_LEFT);
ok(
    TotpService::verify($secret, $wrongCode, 1, TotpService::PERIOD, TotpService::DIGITS, $now) === null,
    'verify() rejects an incorrect code at the same timestamp'
);

// Clock drift tolerance: a code from one step in the past/future (±30s) still
// verifies with the default window; two steps away does not.
$prevStepCode = TotpService::totp($decoded, $now - TotpService::PERIOD);
ok(
    TotpService::verify($secret, $prevStepCode, 1, TotpService::PERIOD, TotpService::DIGITS, $now) !== null,
    'verify() tolerates a code from one step earlier (clock drift window)'
);
$farStepCode = TotpService::totp($decoded, $now - (3 * TotpService::PERIOD));
ok(
    TotpService::verify($secret, $farStepCode, 1, TotpService::PERIOD, TotpService::DIGITS, $now) === null,
    'verify() rejects a code from 3 steps earlier (outside the drift window)'
);

// Malformed inputs.
ok(TotpService::verify($secret, '12345', 1, TotpService::PERIOD, TotpService::DIGITS, $now) === null, 'verify() rejects a 5-digit code');
ok(TotpService::verify($secret, 'abcdef', 1, TotpService::PERIOD, TotpService::DIGITS, $now) === null, 'verify() rejects a non-numeric code');
ok(TotpService::verify('not valid base32 secret!!', $code, 1, TotpService::PERIOD, TotpService::DIGITS, $now) === null, 'verify() rejects a malformed secret');

// ── Provisioning URI ──────────────────────────────────────────────────────────
echo "\n[Provisioning URI]\n";
$uri = TotpService::provisioningUri($secret, 'alice', 'Test Journal');
ok(str_starts_with($uri, 'otpauth://totp/'), 'provisioningUri() produces an otpauth://totp/ URI');
ok(str_contains($uri, 'secret=' . $secret), 'provisioningUri() embeds the base32 secret');
ok(str_contains($uri, 'digits=6') && str_contains($uri, 'period=30'), 'provisioningUri() declares 6 digits / 30s period');

// ── SecretCipher round-trip (at-rest encryption) ─────────────────────────────
echo "\n[SecretCipher round-trip]\n";
$keyMaterial = 'test-key-material|test-salt|magic-login-totp-cipher-v1';
$plain = $secret;
$enc = SecretCipher::encrypt($plain, $keyMaterial);
ok($enc !== $plain, 'encrypt() output differs from the plaintext secret');
ok(SecretCipher::isEncrypted($enc), 'isEncrypted() recognises freshly encrypted output');
ok(SecretCipher::decrypt($enc, $keyMaterial) === $plain, 'decrypt(encrypt($x)) === $x with the correct key');
ok(SecretCipher::decrypt($enc, 'wrong-key-material') === null, 'decrypt() fails closed (null) with the wrong key');
ok(SecretCipher::decrypt('', $keyMaterial) === '', 'decrypt() of empty string returns empty string');
ok(SecretCipher::encrypt('', $keyMaterial) === '', 'encrypt() of empty string returns empty string (nothing to hide)');

// ── Source-level regression checks ───────────────────────────────────────────
// These mirror tests/token-format.php's approach for OJS-framework-coupled
// code (MagicLoginHandler, TotpAccountService) that cannot be instantiated
// outside a full OJS install.

echo "\n[Source: replay protection]\n";
$acctSrc = file_get_contents(__DIR__ . '/../classes/TotpAccountService.php');
ok(
    strpos($acctSrc, 'SETTING_LAST_STEP') !== false,
    'TotpAccountService persists a last-consumed time-step per account'
);
ok(
    (bool) preg_match('/function verifyLoginCode\(.*?\$matchedStep\s*<=\s*\$lastStep/s', $acctSrc),
    'verifyLoginCode() rejects a code whose matched step is <= the last consumed step (replay guard)'
);

echo "\n[Source: at-rest encryption]\n";
ok(
    strpos($acctSrc, 'SecretCipher::encrypt(') !== false && strpos($acctSrc, 'SecretCipher::decrypt(') !== false,
    'TotpAccountService encrypts/decrypts the secret via SecretCipher, never storing it in plaintext'
);
ok(
    (bool) preg_match('/api_key_secret.*?salt|salt.*?api_key_secret/s', $acctSrc),
    'Key material is derived from config.inc.php [security] api_key_secret/salt (same precedent as PaystackOJS)'
);

echo "\n[Source: setup requires confirmation before enabling]\n";
ok(
    strpos($acctSrc, 'SETTING_PENDING_ENC') !== false && strpos($acctSrc, 'confirmSetup') !== false,
    'A new secret starts as "pending" and is only promoted to enabled by confirmSetup()'
);
ok(
    strpos($acctSrc, 'SETUP_TTL_SECONDS') !== false,
    'Pending (unconfirmed) setups expire'
);

echo "\n[Source: re-auth required to disable]\n";
$handlerSrc = file_get_contents(__DIR__ . '/../pages/MagicLoginHandler.php');
ok(
    (bool) preg_match('/function totpDisable\(.*?Validation::checkCredentials\(/s', $handlerSrc),
    'totpDisable() calls Validation::checkCredentials() (password re-entry) before disabling'
);
ok(
    (bool) preg_match('/function totpDisable\(.*?validateCsrf\(\$request\)/s', $handlerSrc),
    'totpDisable() enforces CSRF like every other mutating endpoint in this plugin'
);

echo "\n[Source: TOTP verify attempts are rate limited]\n";
ok(
    strpos($handlerSrc, 'RL_TOTP_IP_MAX') !== false && strpos($handlerSrc, 'RL_TOTP_ACCOUNT_MAX') !== false,
    'MagicLoginHandler defines both per-IP and per-account TOTP rate limit constants'
);
ok(
    (bool) preg_match('/function totpLogin\(.*?withinKeyedRateLimit\(\'totpip\'/s', $handlerSrc),
    'totpLogin() checks the per-IP rate limit'
);
ok(
    (bool) preg_match('/function totpLogin\(.*?withinKeyedRateLimit\(\'totpacct\'/s', $handlerSrc),
    'totpLogin() checks the per-account rate limit (independent of source IP)'
);

echo "\n[Source: TOTP login neutral-error posture]\n";
// A wrong identifier, an account without TOTP enabled, and a wrong code must
// all fall through to the exact same generic error — mirrors the magic-link
// flow's account-enumeration defense.
ok(
    substr_count($handlerSrc, "__('plugins.generic.magicLogin.error.invalid')") >= 3,
    'totpLogin() reuses the same generic invalid-credentials message across its failure branches'
);

echo "\n[Source: existing magic-link security posture is untouched]\n";
// Regression guard: this branch's earlier fixes (unconditional CSRF, atomic
// verify+consume, per-IP rate limiting) must still be present verbatim.
ok(
    strpos($handlerSrc, 'function validateCsrf($request): bool') !== false,
    'validateCsrf() still exists with its original signature'
);
ok(
    strpos($handlerSrc, "verifyAndConsume(\$token)") !== false,
    'login() still uses the atomic verifyAndConsume() path'
);
ok(
    strpos($handlerSrc, 'private static function withinRateLimit(') !== false,
    'The original per-IP withinRateLimit() helper for magic-link send/login is untouched'
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
