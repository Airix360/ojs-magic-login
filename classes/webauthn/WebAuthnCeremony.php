<?php

/**
 * @file classes/webauthn/WebAuthnCeremony.php
 *
 * @class WebAuthnCeremony
 *
 * @brief Verifies WebAuthn registration ("attestation") and authentication
 * ("assertion") ceremonies per the W3C WebAuthn Level 2 spec, sections 7.1
 * and 7.2 — the parts of those algorithms that matter for a relying party
 * that does NOT verify attestation statement signatures (see README: that
 * is a deliberate, documented scope cut, not an oversight. The security
 * guarantee for this plugin comes entirely from assertion signature
 * verification at login time, which IS fully implemented and covered by
 * tests/webauthn-format.php against real generated keys).
 *
 * Steps intentionally NOT implemented (again, by design, not omission):
 *  - Attestation statement signature verification / trust chain checking
 *    (would require bundling X.509 parsing and a FIDO Metadata Service
 *    client — a much larger undertaking with no bearing on the actual
 *    login security guarantee, which rests on the assertion signature).
 *  - Extensions processing (none are requested).
 */

namespace APP\plugins\generic\magicLogin\classes\webauthn;

class WebAuthnCeremony
{
    private const FLAG_USER_PRESENT = 0x01;
    private const FLAG_USER_VERIFIED = 0x04;
    private const FLAG_ATTESTED_CREDENTIAL_DATA = 0x40;

    /**
     * @param array $credential Decoded JSON from navigator.credentials.create()'s response,
     *   shape: {id, rawId, response: {clientDataJSON, attestationObject, transports?}}
     * @return array{credentialId: string, publicKeyPem: string, alg: int, aaguid: ?string, transports: array}
     */
    public static function verifyRegistration(
        array $credential,
        string $expectedChallengeB64Url,
        string $expectedOrigin,
        string $rpId
    ): array {
        $clientDataJSON = self::b64urlDecode((string) ($credential['response']['clientDataJSON'] ?? ''));
        $clientData = json_decode($clientDataJSON, true);
        if (!is_array($clientData)) {
            throw new \RuntimeException('WebAuthn: malformed clientDataJSON');
        }
        if (($clientData['type'] ?? null) !== 'webauthn.create') {
            throw new \RuntimeException('WebAuthn: unexpected clientData.type for registration');
        }
        self::checkChallengeAndOrigin($clientData, $expectedChallengeB64Url, $expectedOrigin);

        $attestationObjectRaw = self::b64urlDecode((string) ($credential['response']['attestationObject'] ?? ''));
        $attestationObject = Cbor::decode($attestationObjectRaw);
        if (!is_array($attestationObject) || !isset($attestationObject['authData'])) {
            throw new \RuntimeException('WebAuthn: malformed attestationObject');
        }

        $authData = (string) $attestationObject['authData'];
        $parsed = self::parseAuthData($authData, requireAttestedCredentialData: true);

        self::checkRpIdHash($parsed['rpIdHash'], $rpId);
        if (!($parsed['flags'] & self::FLAG_USER_PRESENT)) {
            throw new \RuntimeException('WebAuthn: user-present flag not set during registration');
        }

        $coseKey = Cbor::decode($parsed['coseKeyBytes']);
        $converted = Cose::toPem($coseKey);

        $transports = $credential['response']['transports'] ?? [];
        if (!is_array($transports)) {
            $transports = [];
        }

        return [
            'credentialId' => self::b64urlEncode($parsed['credentialId']),
            'publicKeyPem' => $converted['pem'],
            'alg' => $converted['alg'],
            'aaguid' => $parsed['aaguid'] !== str_repeat("\x00", 16) ? bin2hex($parsed['aaguid']) : null,
            'transports' => array_values(array_filter($transports, 'is_string')),
        ];
    }

    /**
     * @param array $credential Decoded JSON from navigator.credentials.get()'s response,
     *   shape: {id, rawId, response: {clientDataJSON, authenticatorData, signature, userHandle?}}
     * @return array{signCount: int}
     */
    public static function verifyAssertion(
        array $credential,
        string $expectedChallengeB64Url,
        string $expectedOrigin,
        string $rpId,
        string $publicKeyPem
    ): array {
        $clientDataJSON = self::b64urlDecode((string) ($credential['response']['clientDataJSON'] ?? ''));
        $clientData = json_decode($clientDataJSON, true);
        if (!is_array($clientData)) {
            throw new \RuntimeException('WebAuthn: malformed clientDataJSON');
        }
        if (($clientData['type'] ?? null) !== 'webauthn.get') {
            throw new \RuntimeException('WebAuthn: unexpected clientData.type for authentication');
        }
        self::checkChallengeAndOrigin($clientData, $expectedChallengeB64Url, $expectedOrigin);

        $authData = self::b64urlDecode((string) ($credential['response']['authenticatorData'] ?? ''));
        $parsed = self::parseAuthData($authData, requireAttestedCredentialData: false);

        self::checkRpIdHash($parsed['rpIdHash'], $rpId);
        if (!($parsed['flags'] & self::FLAG_USER_PRESENT)) {
            throw new \RuntimeException('WebAuthn: user-present flag not set during authentication');
        }

        $signature = self::b64urlDecode((string) ($credential['response']['signature'] ?? ''));
        $signedData = $authData . hash('sha256', $clientDataJSON, true);

        $result = openssl_verify($signedData, $signature, $publicKeyPem, OPENSSL_ALGO_SHA256);
        if ($result !== 1) {
            throw new \RuntimeException('WebAuthn: assertion signature verification failed');
        }

        return ['signCount' => $parsed['signCount']];
    }

    private static function checkChallengeAndOrigin(array $clientData, string $expectedChallengeB64Url, string $expectedOrigin): void
    {
        $challenge = (string) ($clientData['challenge'] ?? '');
        // Compare as raw bytes (both sides may use padded/unpadded base64url) rather than string equality on the encoded form.
        if (!hash_equals(self::b64urlDecode($expectedChallengeB64Url), self::b64urlDecode($challenge))) {
            throw new \RuntimeException('WebAuthn: challenge mismatch');
        }
        $origin = (string) ($clientData['origin'] ?? '');
        if (!hash_equals($expectedOrigin, $origin)) {
            throw new \RuntimeException('WebAuthn: origin mismatch');
        }
    }

    private static function checkRpIdHash(string $rpIdHash, string $rpId): void
    {
        if (!hash_equals(hash('sha256', $rpId, true), $rpIdHash)) {
            throw new \RuntimeException('WebAuthn: RP ID hash mismatch');
        }
    }

    /**
     * Parse the authenticatorData structure (spec section 6.1):
     * rpIdHash(32) | flags(1) | signCount(4) | [attestedCredentialData] | [extensions]
     * attestedCredentialData = aaguid(16) | credIdLen(2) | credId(credIdLen) | credentialPublicKey (CBOR, variable length)
     */
    private static function parseAuthData(string $authData, bool $requireAttestedCredentialData): array
    {
        if (strlen($authData) < 37) {
            throw new \RuntimeException('WebAuthn: authData too short');
        }
        $rpIdHash = substr($authData, 0, 32);
        $flags = ord($authData[32]);
        $signCount = unpack('N', substr($authData, 33, 4))[1];

        $aaguid = null;
        $credentialId = '';
        $coseKeyBytes = '';

        if ($flags & self::FLAG_ATTESTED_CREDENTIAL_DATA) {
            $offset = 37;
            if (strlen($authData) < $offset + 18) {
                throw new \RuntimeException('WebAuthn: authData truncated in attestedCredentialData header');
            }
            $aaguid = substr($authData, $offset, 16);
            $offset += 16;
            $credIdLen = unpack('n', substr($authData, $offset, 2))[1];
            $offset += 2;
            if (strlen($authData) < $offset + $credIdLen) {
                throw new \RuntimeException('WebAuthn: authData truncated in credential ID');
            }
            $credentialId = substr($authData, $offset, $credIdLen);
            $offset += $credIdLen;

            // The COSE key is CBOR and may not run to the end of the buffer
            // (extensions can follow) — decode with allowTrailing to find
            // exactly how many bytes it consumed.
            [, $consumed] = Cbor::decodeWithLength(substr($authData, $offset));
            $coseKeyBytes = substr($authData, $offset, $consumed);
        } elseif ($requireAttestedCredentialData) {
            throw new \RuntimeException('WebAuthn: attestedCredentialData flag not set during registration');
        }

        return [
            'rpIdHash' => $rpIdHash,
            'flags' => $flags,
            'signCount' => $signCount,
            'aaguid' => $aaguid ?? str_repeat("\x00", 16),
            'credentialId' => $credentialId,
            'coseKeyBytes' => $coseKeyBytes,
        ];
    }

    public static function b64urlEncode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    public static function b64urlDecode(string $data): string
    {
        $padded = str_pad(strtr($data, '-_', '+/'), strlen($data) % 4 === 0 ? strlen($data) : strlen($data) + (4 - strlen($data) % 4), '=');
        $decoded = base64_decode($padded, true);
        return $decoded === false ? '' : $decoded;
    }
}
