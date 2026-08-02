<?php

/**
 * @file classes/SecretCipher.php
 *
 * Distributed under the GNU GPL v3.
 *
 * @class SecretCipher
 *
 * @brief Symmetric encryption helper for at-rest secrets (TOTP shared
 * secrets) stored in `user_settings`. Prefers libsodium (secretbox /
 * XSalsa20-Poly1305), falling back to OpenSSL AES-256-GCM when sodium isn't
 * available. Both are bundled with PHP by default, so no new Composer
 * dependency is introduced.
 *
 * Ported verbatim (algorithm + format) from the sibling PaystackOJS plugin's
 * classes/SecretCipher.php, which already established this at-rest
 * encryption pattern for a different per-context secret (Paystack API keys).
 * Reusing the same scheme here — rather than inventing a new one — keeps a
 * single, already-reviewed approach across this author's OJS plugins.
 *
 * Ciphertext is tagged with a short prefix identifying the scheme used, so
 * legacy plaintext values (should any ever exist) are still readable:
 * decrypt() returns them unchanged.
 *
 * Kept dependency-free (no OJS framework classes) so it can be unit tested
 * in isolation — see tests/totp-format.php.
 */

namespace APP\plugins\generic\magicLogin\classes;

class SecretCipher
{
    private const PREFIX_SODIUM  = 'mlxsec1:';
    private const PREFIX_OPENSSL = 'mlxsec2:';

    /**
     * Encrypt a plaintext secret for storage. Returns '' for '' (nothing to
     * hide), otherwise a prefixed, base64-encoded blob.
     */
    public static function encrypt(string $plaintext, string $keyMaterial): string
    {
        if ($plaintext === '') {
            return '';
        }
        $key = self::deriveKey($keyMaterial);

        if (function_exists('sodium_crypto_secretbox')) {
            $nonce  = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
            $cipher = sodium_crypto_secretbox($plaintext, $nonce, $key);
            return self::PREFIX_SODIUM . base64_encode($nonce . $cipher);
        }

        if (function_exists('openssl_encrypt')) {
            $iv     = random_bytes(12);
            $tag    = '';
            $cipher = openssl_encrypt($plaintext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);
            if ($cipher === false) {
                throw new \RuntimeException('SecretCipher: openssl_encrypt failed.');
            }
            return self::PREFIX_OPENSSL . base64_encode($iv . $tag . $cipher);
        }

        throw new \RuntimeException('SecretCipher: neither sodium nor openssl extensions are available; cannot encrypt secrets at rest.');
    }

    /**
     * Decrypt a value previously produced by encrypt(). Values without a
     * recognised prefix are treated as legacy plaintext and returned as-is.
     * Returns null only when a value IS tagged as encrypted but fails to
     * decrypt (wrong/rotated key, corruption, missing crypto extension).
     */
    public static function decrypt(?string $stored, string $keyMaterial): ?string
    {
        if ($stored === null || $stored === '') {
            return $stored;
        }

        if (strpos($stored, self::PREFIX_SODIUM) === 0) {
            if (!function_exists('sodium_crypto_secretbox_open')) {
                return null;
            }
            $raw = base64_decode(substr($stored, strlen(self::PREFIX_SODIUM)), true);
            if ($raw === false || strlen($raw) <= SODIUM_CRYPTO_SECRETBOX_NONCEBYTES) {
                return null;
            }
            $nonce  = substr($raw, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
            $cipher = substr($raw, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
            $plain  = sodium_crypto_secretbox_open($cipher, $nonce, self::deriveKey($keyMaterial));
            return $plain === false ? null : $plain;
        }

        if (strpos($stored, self::PREFIX_OPENSSL) === 0) {
            if (!function_exists('openssl_decrypt')) {
                return null;
            }
            $raw = base64_decode(substr($stored, strlen(self::PREFIX_OPENSSL)), true);
            if ($raw === false || strlen($raw) <= 28) {
                return null;
            }
            $iv     = substr($raw, 0, 12);
            $tag    = substr($raw, 12, 16);
            $cipher = substr($raw, 28);
            $plain  = openssl_decrypt($cipher, 'aes-256-gcm', self::deriveKey($keyMaterial), OPENSSL_RAW_DATA, $iv, $tag);
            return $plain === false ? null : $plain;
        }

        // Legacy plaintext (pre-dates encryption support).
        return $stored;
    }

    /** Whether a stored value is already in encrypted form (vs. legacy plaintext). */
    public static function isEncrypted(?string $stored): bool
    {
        return $stored !== null
            && (strpos($stored, self::PREFIX_SODIUM) === 0 || strpos($stored, self::PREFIX_OPENSSL) === 0);
    }

    /**
     * Derive a fixed-length 32-byte key suitable for both secretbox and
     * AES-256-GCM from arbitrary-length key material.
     */
    private static function deriveKey(string $keyMaterial): string
    {
        return hash('sha256', $keyMaterial, true);
    }
}
