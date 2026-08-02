<?php

/**
 * @file classes/webauthn/WebAuthnCredentialService.php
 *
 * @class WebAuthnCredentialService
 *
 * @brief CRUD for `magic_login_webauthn_credentials`. Mirrors
 * TotpAccountService's separation of storage from verification logic —
 * WebAuthnCeremony does the actual cryptographic work and calls here only to
 * persist/read rows.
 */

namespace APP\plugins\generic\magicLogin\classes\webauthn;

use Illuminate\Support\Facades\DB;

class WebAuthnCredentialService
{
    /** @return array<int, object> */
    public function listForUser(int $userId): array
    {
        return DB::table('magic_login_webauthn_credentials')
            ->where('user_id', $userId)
            ->orderByDesc('created_at')
            ->get()
            ->all();
    }

    public function countForUser(int $userId): int
    {
        return (int) DB::table('magic_login_webauthn_credentials')
            ->where('user_id', $userId)
            ->count();
    }

    public function findByCredentialId(string $credentialIdBase64Url): ?object
    {
        $row = DB::table('magic_login_webauthn_credentials')
            ->where('credential_id', $credentialIdBase64Url)
            ->first();
        return $row ?: null;
    }

    public function store(
        int $userId,
        string $credentialIdBase64Url,
        string $publicKeyPem,
        int $coseAlg,
        array $transports,
        ?string $aaguid,
        ?string $nickname
    ): void {
        DB::table('magic_login_webauthn_credentials')->insert([
            'user_id' => $userId,
            'credential_id' => $credentialIdBase64Url,
            'public_key_pem' => $publicKeyPem,
            'cose_alg' => $coseAlg,
            'transports' => $transports ? json_encode(array_values($transports)) : null,
            'aaguid' => $aaguid,
            'sign_count' => 0,
            'nickname' => $nickname,
            'created_at' => now(),
        ]);
    }

    public function updateSignCount(int $credentialRecordId, int $signCount): void
    {
        DB::table('magic_login_webauthn_credentials')
            ->where('credential_record_id', $credentialRecordId)
            ->update(['sign_count' => $signCount, 'last_used_at' => now()]);
    }

    /** Delete a credential — caller must have already verified it belongs to $userId. */
    public function delete(int $credentialRecordId, int $userId): bool
    {
        return DB::table('magic_login_webauthn_credentials')
            ->where('credential_record_id', $credentialRecordId)
            ->where('user_id', $userId)
            ->delete() > 0;
    }
}
