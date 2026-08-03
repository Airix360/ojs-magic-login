<?php

/**
 * @file classes/TokenService.php
 *
 * Issue / verify / consume magic-login tokens.
 *
 * Security model
 * ──────────────
 *  • Selector-verifier scheme: the URL carries a random selector (lookup key)
 *    and a random verifier (secret). Only sha256(verifier) is stored, so a
 *    database read never reveals a usable token. Lookup is by selector;
 *    comparison is constant-time (hash_equals).
 *  • Selectors are 16 random bytes (128-bit) encoded as 32 lowercase hex chars.
 *  • Verifiers are 32 random bytes (256-bit) encoded as url-safe base64.
 *  • Single-use: consume() wipes all token fields the moment a login succeeds.
 *  • Short expiry (configurable, default 15 min).
 *  • Per-account rate limit: minimum interval between sends (TokenService).
 *  • No user enumeration: the send endpoint always shows the same neutral page.
 *  • Disabled accounts are rejected at every stage (issue, verify, session).
 *
 * Storage: OJS user_settings (one active token per user; issuing a new token
 * silently supersedes the previous one). For high-volume installations a
 * dedicated indexed table would be preferable — see README.
 */

namespace APP\plugins\generic\magicLogin\classes;

use APP\facades\Repo;
use Illuminate\Support\Facades\DB;
use PKP\user\User;

class TokenService
{
    private const SETTING_SELECTOR  = 'magicLoginSelector';
    private const SETTING_HASH      = 'magicLoginVerifierHash';
    private const SETTING_EXPIRY    = 'magicLoginExpiry';
    private const SETTING_LAST_SENT = 'magicLoginLastSent';

    /** Maximum selector length accepted in DB lookups (actual value is 32). */
    private const SELECTOR_MAX_LEN = 64;

    /**
     * Issue a token for $user.
     *
     * Returns the raw "selector.verifier" string to embed in the email link,
     * or null if the per-account minimum interval has not elapsed yet.
     * The caller must show a neutral message regardless of the return value.
     */
    public function issue(User $user, int $ttlSeconds, int $minIntervalSeconds): ?string
    {
        if ($user->getDisabled()) {
            return null;
        }

        $now      = time();
        $lastSent = (int) $this->getSetting($user->getId(), self::SETTING_LAST_SENT);
        if ($lastSent && ($now - $lastSent) < $minIntervalSeconds) {
            return null; // too soon — caller still shows the neutral message
        }

        // selector: random 16-byte hex (128-bit, used only for DB lookup)
        $selector = bin2hex(random_bytes(16));
        // verifier: random 32-byte url-safe base64 (256-bit secret, never stored)
        $verifier = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');

        // Write directly to user_settings — Repo::user()->edit() only persists
        // schema-defined properties and silently drops arbitrary custom keys.
        $this->saveSetting($user->getId(), self::SETTING_SELECTOR,  $selector);
        $this->saveSetting($user->getId(), self::SETTING_HASH,      hash('sha256', $verifier));
        $this->saveSetting($user->getId(), self::SETTING_EXPIRY,    (string)($now + $ttlSeconds));
        $this->saveSetting($user->getId(), self::SETTING_LAST_SENT, (string)$now);

        return $selector . '.' . $verifier;
    }

    /**
     * Verify a "selector.verifier" token.
     *
     * Returns the matching, active, non-disabled User on success, or null on
     * any failure (unknown selector, wrong verifier, expired, disabled account).
     *
     * Does NOT consume the token — call consume() only after the session has
     * been established successfully.
     */
    public function verify(string $token): ?User
    {
        $parts = explode('.', $token, 2);
        if (count($parts) !== 2) {
            return null;
        }
        [$selector, $verifier] = $parts;

        // Reject empty or suspiciously long selectors before touching the DB.
        if ($selector === '' || $verifier === '' || strlen($selector) > self::SELECTOR_MAX_LEN) {
            return null;
        }

        // Look up by selector (DB stores only the selector, never the verifier).
        $userId = DB::table('user_settings')
            ->where('setting_name', self::SETTING_SELECTOR)
            ->where('setting_value', $selector)
            ->value('user_id');

        if (!$userId) {
            return null;
        }

        $user = Repo::user()->get((int) $userId);
        if (!$user || $user->getDisabled()) {
            return null;
        }

        $storedHash = (string) $this->getSetting((int) $userId, self::SETTING_HASH);
        $expiry     = (int)    $this->getSetting((int) $userId, self::SETTING_EXPIRY);

        if (!$storedHash || time() > $expiry) {
            return null; // expired or already consumed
        }

        // Constant-time comparison prevents timing-based verifier enumeration.
        if (!hash_equals($storedHash, hash('sha256', $verifier))) {
            return null;
        }

        return $user;
    }

    /**
     * Invalidate the user's current token (single-use enforcement).
     * Must be called immediately before or during session creation.
     *
     * Kept for callers (if any) that already hold a verified $user and
     * intentionally want to invalidate whatever token currently exists for
     * them. Login itself must use verifyAndConsume() instead, so that
     * verification and consumption happen atomically against the *same*
     * token — see verifyAndConsume() for why.
     */
    public function consume(User $user): void
    {
        DB::table('user_settings')
            ->where('user_id', $user->getId())
            ->whereIn('setting_name', [
                self::SETTING_SELECTOR,
                self::SETTING_HASH,
                self::SETTING_EXPIRY,
            ])
            ->delete();
    }

    /**
     * Atomically verify a "selector.verifier" token and consume it in the
     * same transaction, so two concurrent login requests presenting the same
     * token cannot both pass verification before either consumes it.
     *
     * The selector row is locked (SELECT ... FOR UPDATE) before the hash and
     * expiry are checked, and the delete that consumes the token is scoped
     * to that exact selector (not just the user ID) and its affected-row
     * count is checked — if a concurrent request already deleted it, this
     * call fails closed and returns null instead of returning the user a
     * second time.
     *
     * Returns the matching, active, non-disabled User on success, or null on
     * any failure (unknown selector, wrong verifier, expired, disabled
     * account, or lost the race to consume the token).
     */
    public function verifyAndConsume(string $token): ?User
    {
        $parts = explode('.', $token, 2);
        if (count($parts) !== 2) {
            return null;
        }
        [$selector, $verifier] = $parts;

        if ($selector === '' || $verifier === '' || strlen($selector) > self::SELECTOR_MAX_LEN) {
            return null;
        }

        return DB::transaction(function () use ($selector, $verifier) {
            // Lock the selector row for the duration of the transaction so a
            // concurrent request for the same token blocks here until this
            // transaction commits (and consumes the token), rather than both
            // requests reading the row as still-valid.
            $row = DB::table('user_settings')
                ->where('setting_name', self::SETTING_SELECTOR)
                ->where('setting_value', $selector)
                ->lockForUpdate()
                ->first(['user_id']);

            if (!$row) {
                return null;
            }
            $userId = (int) $row->user_id;

            $user = Repo::user()->get($userId);
            if (!$user || $user->getDisabled()) {
                return null;
            }

            $storedHash = (string) $this->getSetting($userId, self::SETTING_HASH);
            $expiry     = (int)    $this->getSetting($userId, self::SETTING_EXPIRY);

            if (!$storedHash || time() > $expiry) {
                return null; // expired or already consumed
            }

            if (!hash_equals($storedHash, hash('sha256', $verifier))) {
                return null;
            }

            // Consume: scoped to this exact selector (not just the user ID),
            // so an unrelated token issued for the same user in between is
            // never accidentally deleted. Check the affected-row count so a
            // request that loses the race (selector already deleted by a
            // concurrent winner) fails closed instead of returning the user.
            $deleted = DB::table('user_settings')
                ->where('user_id', $userId)
                ->where('setting_name', self::SETTING_SELECTOR)
                ->where('setting_value', $selector)
                ->delete();

            if ($deleted === 0) {
                return null;
            }

            DB::table('user_settings')
                ->where('user_id', $userId)
                ->whereIn('setting_name', [self::SETTING_HASH, self::SETTING_EXPIRY])
                ->delete();

            return $user;
        });
    }

    // ── Private DB helpers ────────────────────────────────────────────────────

    /** Read a single token setting directly from user_settings. */
    private function getSetting(int $userId, string $name): ?string
    {
        return DB::table('user_settings')
            ->where('user_id', $userId)
            ->where('setting_name', $name)
            ->value('setting_value');
    }

    /** Upsert a single token setting directly into user_settings. */
    private function saveSetting(int $userId, string $name, string $value): void
    {
        DB::table('user_settings')->upsert(
            [['user_id' => $userId, 'locale' => '', 'setting_name' => $name, 'setting_value' => $value]],
            ['user_id', 'locale', 'setting_name'],
            ['setting_value']
        );
    }
}
