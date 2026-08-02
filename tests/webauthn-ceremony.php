<?php

/**
 * @file tests/webauthn-ceremony.php
 *
 * End-to-end self-check for classes/webauthn/WebAuthnCeremony.php. Builds
 * real authenticatorData/attestationObject/clientDataJSON byte structures
 * exactly as a browser+authenticator would (using a real generated P-256
 * key and a real ECDSA signature), runs them through
 * WebAuthnCeremony::verifyRegistration()/verifyAssertion(), and checks both
 * the success path and that tampering with any single input (challenge,
 * origin, RP ID, signature, signed bytes) is rejected. This is the test
 * that actually matters for this feature — the byte-offset arithmetic in
 * parseAuthData() is exactly the kind of code that looks right and isn't.
 */

require_once __DIR__ . '/../classes/webauthn/Cbor.php';
require_once __DIR__ . '/../classes/webauthn/Cose.php';
require_once __DIR__ . '/../classes/webauthn/WebAuthnCeremony.php';

use APP\plugins\generic\magicLogin\classes\webauthn\WebAuthnCeremony;

$failures = 0;
$total = 0;
function check(string $label, bool $condition): void
{
    global $failures, $total;
    $total++;
    if (!$condition) {
        $failures++;
        fwrite(STDERR, "FAIL: $label\n");
    } else {
        echo "PASS: $label\n";
    }
}
function b64url(string $data): string
{
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}
function cborBytes(string $bytes): string
{
    $len = strlen($bytes);
    if ($len < 24) {
        return chr(0x40 | $len) . $bytes;
    }
    return chr(0x58) . chr($len) . $bytes;
}
function cborNegInt(int $magnitude): string
{
    return $magnitude < 24 ? chr(0x20 | $magnitude) : chr(0x38) . chr($magnitude);
}
function cborEc2CoseKey(string $x, string $y): string
{
    return chr(0xA5) . chr(0x01) . chr(0x02) . chr(0x03) . chr(0x26) . chr(0x20) . chr(0x01)
        . chr(0x21) . cborBytes($x) . chr(0x22) . cborBytes($y);
}

// ── Shared fixtures ──────────────────────────────────────────────────────

$rpId = 'ojs-demo.airixmedia.com';
$origin = 'https://ojs-demo.airixmedia.com';

$ecKey = openssl_pkey_new(['curve_name' => 'prime256v1', 'private_key_type' => OPENSSL_KEYTYPE_EC]);
$details = openssl_pkey_get_details($ecKey);
$x = $details['ec']['x'];
$y = $details['ec']['y'];
$coseKeyBytes = cborEc2CoseKey($x, $y);

$rpIdHash = hash('sha256', $rpId, true);
$aaguid = random_bytes(16);
$credentialId = random_bytes(32);
$credIdB64 = b64url($credentialId);

// ── Registration ceremony ────────────────────────────────────────────────

$regChallenge = random_bytes(32);
$regChallengeB64 = b64url($regChallenge);

$regClientData = json_encode(['type' => 'webauthn.create', 'challenge' => $regChallengeB64, 'origin' => $origin]);

// authData: rpIdHash(32) | flags(1, UP|AT=0x41) | signCount(4, 0) | aaguid(16) | credIdLen(2) | credId | coseKey
$regFlags = chr(0x41); // UP + attestedCredentialData
$regAuthData = $rpIdHash . $regFlags . pack('N', 0) . $aaguid . pack('n', strlen($credentialId)) . $credentialId . $coseKeyBytes;

$attestationObject = chr(0xA3) // map(3): fmt, attStmt, authData
    . chr(0x63) . 'fmt' . chr(0x64) . 'none'
    . chr(0x67) . 'attStmt' . chr(0xA0) // empty map
    . chr(0x68) . 'authData' . cborBytesLong($regAuthData);

function cborBytesLong(string $bytes): string
{
    $len = strlen($bytes);
    if ($len < 256) {
        return chr(0x58) . chr($len) . $bytes;
    }
    return chr(0x59) . pack('n', $len) . $bytes;
}

$regCredential = [
    'id' => $credIdB64,
    'response' => [
        'clientDataJSON' => b64url($regClientData),
        'attestationObject' => b64url($attestationObject),
        'transports' => ['internal'],
    ],
];

$regResult = WebAuthnCeremony::verifyRegistration($regCredential, $regChallengeB64, $origin, $rpId);
check('Registration succeeds with valid input', $regResult['credentialId'] === $credIdB64 && $regResult['alg'] === -7);
check('Registration extracts aaguid', $regResult['aaguid'] === bin2hex($aaguid));
check('Registration extracts transports', $regResult['transports'] === ['internal']);

$storedPem = $regResult['publicKeyPem'];

// Tamper: wrong challenge
try {
    WebAuthnCeremony::verifyRegistration($regCredential, b64url(random_bytes(32)), $origin, $rpId);
    check('Registration rejects wrong challenge', false);
} catch (\RuntimeException $e) {
    check('Registration rejects wrong challenge', str_contains($e->getMessage(), 'challenge'));
}

// Tamper: wrong origin
try {
    WebAuthnCeremony::verifyRegistration($regCredential, $regChallengeB64, 'https://evil.example', $rpId);
    check('Registration rejects wrong origin', false);
} catch (\RuntimeException $e) {
    check('Registration rejects wrong origin', str_contains($e->getMessage(), 'origin'));
}

// Tamper: wrong RP ID
try {
    WebAuthnCeremony::verifyRegistration($regCredential, $regChallengeB64, $origin, 'evil.example');
    check('Registration rejects wrong RP ID', false);
} catch (\RuntimeException $e) {
    check('Registration rejects wrong RP ID', str_contains($e->getMessage(), 'RP ID'));
}

// ── Authentication ceremony ──────────────────────────────────────────────

$loginChallenge = random_bytes(32);
$loginChallengeB64 = b64url($loginChallenge);
$loginClientData = json_encode(['type' => 'webauthn.get', 'challenge' => $loginChallengeB64, 'origin' => $origin]);
$loginClientDataB64 = b64url($loginClientData);

$loginFlags = chr(0x01); // UP only, no attested credential data
$signCount = 42;
$loginAuthData = $rpIdHash . $loginFlags . pack('N', $signCount);

$signedData = $loginAuthData . hash('sha256', $loginClientData, true);
openssl_sign($signedData, $signature, $ecKey, OPENSSL_ALGO_SHA256);

$assertionCredential = [
    'id' => $credIdB64,
    'response' => [
        'clientDataJSON' => $loginClientDataB64,
        'authenticatorData' => b64url($loginAuthData),
        'signature' => b64url($signature),
    ],
];

$assertionResult = WebAuthnCeremony::verifyAssertion($assertionCredential, $loginChallengeB64, $origin, $rpId, $storedPem);
check('Assertion succeeds with valid signature against the registered public key', $assertionResult['signCount'] === $signCount);

// Tamper: signature over different authData (bit flip)
$badAuthData = $loginAuthData;
$badAuthData[33] = chr(ord($badAuthData[33]) ^ 0xFF);
$badCredential = $assertionCredential;
$badCredential['response']['authenticatorData'] = b64url($badAuthData);
try {
    WebAuthnCeremony::verifyAssertion($badCredential, $loginChallengeB64, $origin, $rpId, $storedPem);
    check('Assertion rejects tampered authenticatorData', false);
} catch (\RuntimeException $e) {
    check('Assertion rejects tampered authenticatorData', str_contains($e->getMessage(), 'signature'));
}

// Tamper: signature reused against a DIFFERENT (unrelated) public key
$otherKey = openssl_pkey_new(['curve_name' => 'prime256v1', 'private_key_type' => OPENSSL_KEYTYPE_EC]);
$otherDetails = openssl_pkey_get_details($otherKey);
$otherCoseKeyBytes = cborEc2CoseKey($otherDetails['ec']['x'], $otherDetails['ec']['y']);
$otherPem = (new ReflectionMethod(\APP\plugins\generic\magicLogin\classes\webauthn\Cose::class, 'toPem'))->invoke(null, \APP\plugins\generic\magicLogin\classes\webauthn\Cbor::decode($otherCoseKeyBytes));
try {
    WebAuthnCeremony::verifyAssertion($assertionCredential, $loginChallengeB64, $origin, $rpId, $otherPem['pem']);
    check('Assertion rejects a signature that does not match the stored credential\'s public key', false);
} catch (\RuntimeException $e) {
    check('Assertion rejects a signature that does not match the stored credential\'s public key', str_contains($e->getMessage(), 'signature'));
}

// Missing user-present flag
$noUpAuthData = $rpIdHash . chr(0x00) . pack('N', $signCount);
$noUpSignedData = $noUpAuthData . hash('sha256', $loginClientData, true);
openssl_sign($noUpSignedData, $noUpSignature, $ecKey, OPENSSL_ALGO_SHA256);
$noUpCredential = $assertionCredential;
$noUpCredential['response']['authenticatorData'] = b64url($noUpAuthData);
$noUpCredential['response']['signature'] = b64url($noUpSignature);
try {
    WebAuthnCeremony::verifyAssertion($noUpCredential, $loginChallengeB64, $origin, $rpId, $storedPem);
    check('Assertion rejects missing user-present flag', false);
} catch (\RuntimeException $e) {
    check('Assertion rejects missing user-present flag', str_contains($e->getMessage(), 'user-present'));
}

echo "\n$total checks, " . ($total - $failures) . " passed, $failures failed.\n";
exit($failures > 0 ? 1 : 0);
