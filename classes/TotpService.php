<?php

/**
 * @file classes/TotpService.php
 *
 * RFC 6238 (TOTP) / RFC 4226 (HOTP) implementation using only PHP's built-in
 * hash_hmac('sha1', ...) — no Composer dependency. This OJS installation's
 * vendor tree (lib/pkp/lib/vendor) was checked first and has no TOTP-capable
 * package installed, so this class implements the algorithm directly. RFC
 * 6238 is compact and well-specified: HOTP(K, C) = truncate(HMAC-SHA1(K, C)),
 * and TOTP is HOTP with the counter derived from the current Unix time.
 *
 * Security notes:
 *  • Secrets are generated with random_bytes() (CSPRNG), 20 bytes (160 bits),
 *    the size RFC 4226 recommends.
 *  • Code comparison uses hash_equals() (constant-time) to avoid a timing
 *    side channel on the 6-digit code.
 *  • verify() accepts a small window (±1 step = ±30s) to tolerate clock
 *    drift between server and authenticator app, and returns the matched
 *    time-step counter so the caller can reject replays of the same code
 *    within its validity window (store "last consumed step" per user).
 *  • This class is intentionally framework-free (no OJS/PKP classes) so it
 *    can be unit tested in isolation against published RFC 4226 test
 *    vectors — see tests/totp-format.php.
 */

namespace APP\plugins\generic\magicLogin\classes;

class TotpService
{
    private const B32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

    public const SECRET_BYTES = 20; // 160-bit, per RFC 4226's recommendation
    public const PERIOD       = 30; // seconds per time-step
    public const DIGITS       = 6;
    public const WINDOW       = 1;  // ± steps tolerated for clock drift

    /** Generate a new random TOTP secret, base32-encoded (for storage/display). */
    public static function generateSecretBase32(): string
    {
        return self::base32Encode(random_bytes(self::SECRET_BYTES));
    }

    /**
     * Build an otpauth:// provisioning URI for display as text and/or
     * encoding into a QR code by the authenticator app's own scanner
     * (e.g. via a URI the user types or a link they open on the same device).
     */
    public static function provisioningUri(string $secretBase32, string $accountLabel, string $issuer): string
    {
        $label = rawurlencode($issuer) . ':' . rawurlencode($accountLabel);
        $query = http_build_query([
            'secret'    => $secretBase32,
            'issuer'    => $issuer,
            'algorithm' => 'SHA1',
            'digits'    => self::DIGITS,
            'period'    => self::PERIOD,
        ]);
        return 'otpauth://totp/' . $label . '?' . $query;
    }

    /**
     * Core RFC 4226 HOTP algorithm: HOTP(K, C).
     *
     * @param string $key     Raw (binary, decoded) secret bytes.
     * @param int    $counter Non-negative counter (for TOTP: floor(time / period)).
     */
    public static function hotp(string $key, int $counter, int $digits = self::DIGITS): string
    {
        // 8-byte big-endian counter. pack('N*', 0, $counter) writes the high
        // 32 bits as 0 and the low 32 bits as $counter — correct as long as
        // $counter fits in 32 bits, true for any wall-clock time / 30s until
        // the year ~4147.
        $binCounter = pack('N*', 0, $counter);
        $hash       = hash_hmac('sha1', $binCounter, $key, true);

        $offset = ord($hash[19]) & 0x0f;
        $binary = ((ord($hash[$offset])     & 0x7f) << 24)
                | ((ord($hash[$offset + 1]) & 0xff) << 16)
                | ((ord($hash[$offset + 2]) & 0xff) << 8)
                |  (ord($hash[$offset + 3]) & 0xff);

        $otp = $binary % (10 ** $digits);
        return str_pad((string) $otp, $digits, '0', STR_PAD_LEFT);
    }

    /** TOTP(K) at a given (or current) Unix timestamp. */
    public static function totp(string $key, ?int $timestamp = null, int $period = self::PERIOD, int $digits = self::DIGITS): string
    {
        $timestamp ??= time();
        $counter = intdiv($timestamp, $period);
        return self::hotp($key, $counter, $digits);
    }

    /**
     * Verify a user-submitted 6-digit code against a base32 secret, tolerating
     * clock drift of up to $window steps in either direction.
     *
     * Returns the matched absolute time-step counter on success (so the
     * caller can persist it and reject a replay of the same code within its
     * still-valid window), or null if the code does not match any step in
     * range or the secret/code are malformed.
     */
    public static function verify(
        string $secretBase32,
        string $code,
        int $window = self::WINDOW,
        int $period = self::PERIOD,
        int $digits = self::DIGITS,
        ?int $now = null
    ): ?int {
        $code = trim($code);
        if (!preg_match('/^\d{' . $digits . '}$/', $code)) {
            return null;
        }

        $key = self::base32Decode($secretBase32);
        if ($key === null || $key === '') {
            return null;
        }

        $now     = $now ?? time();
        $counter = intdiv($now, $period);

        for ($i = -$window; $i <= $window; $i++) {
            $candidate = self::hotp($key, $counter + $i, $digits);
            if (hash_equals($candidate, $code)) {
                return $counter + $i;
            }
        }
        return null;
    }

    // ── Base32 (RFC 4648) ─────────────────────────────────────────────────────
    // PHP has no built-in base32; TOTP secrets are conventionally base32 so
    // they can be typed into an authenticator app manually.

    public static function base32Encode(string $data): string
    {
        if ($data === '') {
            return '';
        }
        $bits = '';
        foreach (str_split($data) as $byte) {
            $bits .= str_pad(decbin(ord($byte)), 8, '0', STR_PAD_LEFT);
        }
        $output = '';
        foreach (str_split($bits, 5) as $chunk) {
            if (strlen($chunk) < 5) {
                $chunk = str_pad($chunk, 5, '0', STR_PAD_RIGHT);
            }
            $output .= self::B32_ALPHABET[bindec($chunk)];
        }
        return $output;
    }

    public static function base32Decode(string $b32): ?string
    {
        $b32 = strtoupper(trim($b32));
        $b32 = rtrim($b32, '=');
        // Authenticator apps sometimes display secrets with spaces; strip them.
        $b32 = str_replace(' ', '', $b32);
        if ($b32 === '' || !preg_match('/^[A-Z2-7]+$/', $b32)) {
            return null;
        }
        $bits = '';
        foreach (str_split($b32) as $char) {
            $pos = strpos(self::B32_ALPHABET, $char);
            if ($pos === false) {
                return null;
            }
            $bits .= str_pad(decbin($pos), 5, '0', STR_PAD_LEFT);
        }
        $bytes = '';
        foreach (str_split($bits, 8) as $byteBits) {
            if (strlen($byteBits) < 8) {
                break; // drop incomplete trailing bits (base32 padding artifact)
            }
            $bytes .= chr(bindec($byteBits));
        }
        return $bytes;
    }
}
