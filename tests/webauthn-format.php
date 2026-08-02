<?php

/**
 * @file tests/webauthn-format.php
 *
 * Self-check for classes/webauthn/{Cbor,Cose}.php — no OJS bootstrap
 * required (bin/php -r style, matching tests/totp-format.php).
 *
 * Rather than trusting a copy-pasted "known" CBOR/COSE test vector, this
 * generates REAL EC/RSA keypairs with openssl, builds the COSE_Key CBOR
 * encoding for each by hand (exercising Cbor's own encoding rules in
 * reverse is out of scope — Cbor only decodes — so the map bytes are
 * assembled directly per RFC 8949 for a map of this exact fixed shape),
 * decodes them back with Cbor::decode(), converts to PEM with Cose::toPem(),
 * and confirms openssl_verify() accepts a real signature made with the
 * matching private key and rejects a tampered one. This proves the actual
 * signature-verification code path end to end, not just that the decoder
 * doesn't crash.
 */

require_once __DIR__ . '/../classes/webauthn/Cbor.php';
require_once __DIR__ . '/../classes/webauthn/Cose.php';

use APP\plugins\generic\magicLogin\classes\webauthn\Cbor;
use APP\plugins\generic\magicLogin\classes\webauthn\Cose;

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

/** Encode a CBOR map { 1: uint(kty), 3: negint(alg), -1: uint(crv), -2: bytes(x,32), -3: bytes(y,32) } — EC2 COSE_Key shape. */
function cborEncodeEc2Key(int $alg, int $crv, string $x, string $y): string
{
    $negint = static fn (int $n) => chr(0x20 | (-1 - $n)); // only valid for -1..-24, which covers -1,-2,-3 and small algs
    $out = chr(0xA5); // map(5)
    $out .= chr(0x01) . chr(0x02); // 1: 2 (kty: EC2)
    $out .= chr(0x03) . ($alg === -7 ? chr(0x26) : encodeNegIntGeneral($alg)); // 3: alg
    $out .= chr(0x20) . chr($crv); // -1: crv
    $out .= chr(0x21) . chr(0x58) . chr(0x20) . $x; // -2: x (32 bytes)
    $out .= chr(0x22) . chr(0x58) . chr(0x20) . $y; // -3: y (32 bytes)
    return $out;
}

/** Encode a CBOR map { 1: uint(kty), 3: negint(alg), -1: bytes(n), -2: bytes(e) } — RSA COSE_Key shape. */
function cborEncodeRsaKey(int $alg, string $n, string $e): string
{
    $out = chr(0xA4); // map(4)
    $out .= chr(0x01) . chr(0x03); // 1: 3 (kty: RSA)
    $out .= chr(0x03) . encodeNegIntGeneral($alg); // 3: alg (-257)
    $out .= chr(0x20) . encodeBytes($n); // -1: n
    $out .= chr(0x21) . encodeBytes($e); // -2: e
    return $out;
}

function encodeNegIntGeneral(int $value): string
{
    $magnitude = -1 - $value; // value = -1 - magnitude
    if ($magnitude < 24) {
        return chr(0x20 | $magnitude);
    }
    if ($magnitude < 256) {
        return chr(0x38) . chr($magnitude);
    }
    return chr(0x39) . pack('n', $magnitude);
}

function encodeBytes(string $bytes): string
{
    $len = strlen($bytes);
    if ($len < 24) {
        return chr(0x40 | $len) . $bytes;
    }
    if ($len < 256) {
        return chr(0x58) . chr($len) . $bytes;
    }
    return chr(0x59) . pack('n', $len) . $bytes;
}

// ── EC2 / ES256 ──────────────────────────────────────────────────────────

$ecKey = openssl_pkey_new(['curve_name' => 'prime256v1', 'private_key_type' => OPENSSL_KEYTYPE_EC]);
check('EC key generation succeeded', $ecKey !== false);
$ecDetails = openssl_pkey_get_details($ecKey);
$x = $ecDetails['ec']['x'];
$y = $ecDetails['ec']['y'];
check('EC public key coordinates are 32 bytes each', strlen($x) === 32 && strlen($y) === 32);

$cborBytes = cborEncodeEc2Key(-7, 1, $x, $y);
$decoded = Cbor::decode($cborBytes);
check('CBOR decode of EC2 COSE_Key round-trips kty/alg/crv/x/y', $decoded[1] === 2 && $decoded[3] === -7 && $decoded[-1] === 1 && $decoded[-2] === $x && $decoded[-3] === $y);

$converted = Cose::toPem($decoded);
check('Cose::toPem reports ES256', $converted['alg'] === Cose::ALG_ES256);

$message = 'webauthn-format self-check ' . bin2hex(random_bytes(8));
openssl_sign($message, $signature, $ecKey, OPENSSL_ALGO_SHA256);
check('openssl_verify accepts a genuine ES256 signature against the Cose-converted PEM', openssl_verify($message, $signature, $converted['pem'], OPENSSL_ALGO_SHA256) === 1);

$tampered = $signature;
$tampered[0] = chr(ord($tampered[0]) ^ 0xFF);
check('openssl_verify rejects a tampered ES256 signature', openssl_verify($message, $tampered, $converted['pem'], OPENSSL_ALGO_SHA256) !== 1);

check('openssl_verify rejects a signature over different data', openssl_verify($message . 'x', $signature, $converted['pem'], OPENSSL_ALGO_SHA256) !== 1);

// ── RSA / RS256 ──────────────────────────────────────────────────────────

$rsaKey = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
check('RSA key generation succeeded', $rsaKey !== false);
$rsaDetails = openssl_pkey_get_details($rsaKey);
$n = $rsaDetails['rsa']['n'];
$e = $rsaDetails['rsa']['e'];

$cborBytesRsa = cborEncodeRsaKey(-257, $n, $e);
$decodedRsa = Cbor::decode($cborBytesRsa);
check('CBOR decode of RSA COSE_Key round-trips kty/alg/n/e', $decodedRsa[1] === 3 && $decodedRsa[3] === -257 && $decodedRsa[-1] === $n && $decodedRsa[-2] === $e);

$convertedRsa = Cose::toPem($decodedRsa);
check('Cose::toPem reports RS256', $convertedRsa['alg'] === Cose::ALG_RS256);

openssl_sign($message, $rsaSignature, $rsaKey, OPENSSL_ALGO_SHA256);
check('openssl_verify accepts a genuine RS256 signature against the Cose-converted PEM', openssl_verify($message, $rsaSignature, $convertedRsa['pem'], OPENSSL_ALGO_SHA256) === 1);

$tamperedRsa = $rsaSignature;
$tamperedRsa[0] = chr(ord($tamperedRsa[0]) ^ 0xFF);
check('openssl_verify rejects a tampered RS256 signature', openssl_verify($message, $tamperedRsa, $convertedRsa['pem'], OPENSSL_ALGO_SHA256) !== 1);

// ── CBOR edge cases ──────────────────────────────────────────────────────

check('CBOR decodes a small array', Cbor::decode(hex2bin('83010203')) === [1, 2, 3]);
check('CBOR decodes an empty map', Cbor::decode(hex2bin('a0')) === []);
check('CBOR decodes false/true/null', Cbor::decode(hex2bin('f4')) === false && Cbor::decode(hex2bin('f5')) === true && Cbor::decode(hex2bin('f6')) === null);

try {
    Cbor::decode(hex2bin('01') . 'trailing garbage');
    check('CBOR rejects trailing data', false);
} catch (\RuntimeException $e) {
    check('CBOR rejects trailing data', true);
}

try {
    Cose::toPem([1 => 1]); // unsupported kty
    check('Cose rejects unsupported key type', false);
} catch (\RuntimeException $e) {
    check('Cose rejects unsupported key type', true);
}

try {
    Cose::toPem([1 => 2, 3 => -8, -1 => 1, -2 => str_repeat("\x01", 32), -3 => str_repeat("\x02", 32)]); // alg -8 not -7
    check('Cose rejects unsupported EC algorithm', false);
} catch (\RuntimeException $e) {
    check('Cose rejects unsupported EC algorithm', true);
}

echo "\n$total checks, " . ($total - $failures) . " passed, $failures failed.\n";
exit($failures > 0 ? 1 : 0);
