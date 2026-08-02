<?php

/**
 * @file classes/TotpAccountService.php
 *
 * Per-user TOTP enrollment state: begin setup, confirm setup, verify a login
 * code, and disable. Storage mirrors TokenService's approach — direct writes
 * to OJS's `user_settings` table, since Repo::user()->edit() only persists
 * schema-defined properties and silently drops arbitrary custom keys.
 *
 * Security model
 * ──────────────
 *  • The TOTP secret is encrypted at rest with SecretCipher (AES-256-GCM /
 *    libsodium secretbox), keyed from OJS's own config.inc.php [security]
 *    api_key_secret + salt — the same pattern the sibling PaystackOJS plugin
 *    uses for its API-key secrets. The key material never lives in the same
 *    table as the ciphertext.
 *  • A newly generated secret is stored as "pending" (unconfirmed) until the
 *    user proves possession of it by entering one valid code; only then is
 *    it promoted to the active, enabled secret. Pending secrets expire after
 *    SETUP_TTL_SECONDS so an abandoned setup attempt cannot be confirmed
 *    much later.
 *  • Replay protection: the time-step matched by a successful verification
 *    is persisted, and any code resolving to a step <= the last consumed
 *    step is rejected — without this, the same 6-digit code could be
 *    replayed for its entire ~90s validity window (±1 step tolerance).
 *  • Disabling requires the caller (TotpHandler) to have already
 *    re-authenticated the user (password re-entry) — this class does not
 *    itself enforce re-auth, since it has no access to request/session state.
 *
 * Rate-limiting login-code verification attempts is the caller's
 * responsibility (see TotpHandler), reusing MagicLoginHandler's existing
 * per-IP sliding-window rate-limit pattern.
 */

namespace APP\plugins\generic\magicLogin\classes;

use Illuminate\Support\Facades\DB;
use PKP\config\Config;
use PKP\user\User;

class TotpAccountService
{
    private const SETTING_SECRET_ENC     = 'magicLoginTotpSecretEnc';
    private const SETTING_ENABLED        = 'magicLoginTotpEnabled';
    private const SETTING_PENDING_ENC    = 'magicLoginTotpPendingSecretEnc';
    private const SETTING_PENDING_CREATED = 'magicLoginTotpPendingCreated';
    private const SETTING_LAST_STEP      = 'magicLoginTotpLastStep';

    /** Unconfirmed setups expire after this many seconds (10 minutes). */
    private const SETUP_TTL_SECONDS = 600;

    public function isEnabled(int $userId): bool
    {
        return (bool) (int) $this->getSetting($userId, self::SETTING_ENABLED);
    }

    /**
     * Start (or restart) TOTP setup for $user: generates a fresh secret,
     * stores it encrypted as "pending", and returns the plaintext secret and
     * its otpauth:// URI for one-time display. The plaintext secret is never
     * persisted — only the encrypted form is stored.
     */
    public function beginSetup(User $user, string $issuer): array
    {
        $secret = TotpService::generateSecretBase32();

        $this->saveSetting($user->getId(), self::SETTING_PENDING_ENC, SecretCipher::encrypt($secret, $this->keyMaterial()));
        $this->saveSetting($user->getId(), self::SETTING_PENDING_CREATED, (string) time());

        return [
            'secret' => $secret,
            'uri'    => TotpService::provisioningUri($secret, $user->getUsername(), $issuer),
        ];
    }

    /**
     * Return the user's in-progress pending setup if one still exists and
     * hasn't expired (so a mistyped confirmation code doesn't force a
     * re-scan of a brand new QR/secret on every retry); otherwise starts a
     * fresh one via beginSetup().
     */
    public function getOrCreatePendingSetup(User $user, string $issuer): array
    {
        $userId  = $user->getId();
        $created = (int) $this->getSetting($userId, self::SETTING_PENDING_CREATED);
        $encSecret = (string) $this->getSetting($userId, self::SETTING_PENDING_ENC);

        if ($created && (time() - $created) <= self::SETUP_TTL_SECONDS && $encSecret !== '') {
            $secret = SecretCipher::decrypt($encSecret, $this->keyMaterial());
            if ($secret !== null && $secret !== '') {
                return [
                    'secret' => $secret,
                    'uri'    => TotpService::provisioningUri($secret, $user->getUsername(), $issuer),
                ];
            }
        }

        return $this->beginSetup($user, $issuer);
    }

    /**
     * Confirm a pending setup by checking a code against the pending secret.
     * On success, promotes the pending secret to the enabled, active secret
     * and clears the pending state. Returns false if there is no pending
     * setup, it has expired, or the code does not verify.
     */
    public function confirmSetup(User $user, string $code): bool
    {
        $userId  = $user->getId();
        $created = (int) $this->getSetting($userId, self::SETTING_PENDING_CREATED);
        if (!$created || (time() - $created) > self::SETUP_TTL_SECONDS) {
            return false;
        }

        $encSecret = (string) $this->getSetting($userId, self::SETTING_PENDING_ENC);
        if ($encSecret === '') {
            return false;
        }
        $secret = SecretCipher::decrypt($encSecret, $this->keyMaterial());
        if ($secret === null || $secret === '') {
            return false;
        }

        $matchedStep = TotpService::verify($secret, $code);
        if ($matchedStep === null) {
            return false;
        }

        // Promote pending -> active, and record the confirmation code's step
        // so it cannot immediately be replayed as a "login" code too.
        $this->saveSetting($userId, self::SETTING_SECRET_ENC, SecretCipher::encrypt($secret, $this->keyMaterial()));
        $this->saveSetting($userId, self::SETTING_ENABLED, '1');
        $this->saveSetting($userId, self::SETTING_LAST_STEP, (string) $matchedStep);
        $this->deleteSettings($userId, [self::SETTING_PENDING_ENC, self::SETTING_PENDING_CREATED]);

        return true;
    }

    /**
     * Verify a login-time TOTP code for $user. Returns true only if TOTP is
     * enabled for the account, the code matches within the allowed clock-drift
     * window, and its time-step has not already been consumed (replay guard).
     */
    public function verifyLoginCode(User $user, string $code): bool
    {
        $userId = $user->getId();
        if (!$this->isEnabled($userId)) {
            return false;
        }

        $encSecret = (string) $this->getSetting($userId, self::SETTING_SECRET_ENC);
        if ($encSecret === '') {
            return false;
        }
        $secret = SecretCipher::decrypt($encSecret, $this->keyMaterial());
        if ($secret === null || $secret === '') {
            return false;
        }

        $matchedStep = TotpService::verify($secret, $code);
        if ($matchedStep === null) {
            return false;
        }

        $lastStep = (int) $this->getSetting($userId, self::SETTING_LAST_STEP);
        if ($matchedStep <= $lastStep) {
            return false; // replay of an already-consumed code
        }

        $this->saveSetting($userId, self::SETTING_LAST_STEP, (string) $matchedStep);
        return true;
    }

    /** Disable TOTP and remove all stored TOTP state for $userId. */
    public function disable(int $userId): void
    {
        $this->deleteSettings($userId, [
            self::SETTING_SECRET_ENC,
            self::SETTING_ENABLED,
            self::SETTING_PENDING_ENC,
            self::SETTING_PENDING_CREATED,
            self::SETTING_LAST_STEP,
        ]);
    }

    /** Discard any in-progress (unconfirmed) setup without affecting an already-enabled secret. */
    public function cancelPendingSetup(int $userId): void
    {
        $this->deleteSettings($userId, [self::SETTING_PENDING_ENC, self::SETTING_PENDING_CREATED]);
    }

    // ── Key material ─────────────────────────────────────────────────────────

    /**
     * Derive the encryption key material from OJS's own config.inc.php
     * [security] api_key_secret / salt — following the same precedent as the
     * sibling PaystackOJS plugin's SecretCipher usage. A plugin-unique
     * domain-separation suffix ensures this key differs from any other
     * plugin deriving a key from the same config values.
     */
    private function keyMaterial(): string
    {
        $apiKeySecret = (string) (Config::getVar('security', 'api_key_secret') ?: '');
        $salt         = (string) (Config::getVar('security', 'salt') ?: '');
        if (trim($apiKeySecret) === '' && trim($salt) === '') {
            throw new \RuntimeException(
                'Cannot derive the magicLogin TOTP secret-encryption key: '
                . 'config.inc.php [security] api_key_secret/salt are not configured.'
            );
        }
        return $apiKeySecret . '|' . $salt . '|magic-login-totp-cipher-v1';
    }

    // ── Private DB helpers (mirrors TokenService) ────────────────────────────

    private function getSetting(int $userId, string $name): ?string
    {
        return DB::table('user_settings')
            ->where('user_id', $userId)
            ->where('setting_name', $name)
            ->value('setting_value');
    }

    private function saveSetting(int $userId, string $name, string $value): void
    {
        DB::table('user_settings')->upsert(
            [['user_id' => $userId, 'locale' => '', 'setting_name' => $name, 'setting_value' => $value]],
            ['user_id', 'locale', 'setting_name'],
            ['setting_value']
        );
    }

    private function deleteSettings(int $userId, array $names): void
    {
        DB::table('user_settings')
            ->where('user_id', $userId)
            ->whereIn('setting_name', $names)
            ->delete();
    }
}
