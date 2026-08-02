<?php

/**
 * @file classes/webauthn/Cose.php
 *
 * @class Cose
 *
 * @brief Converts a COSE_Key (RFC 9053) — the format WebAuthn attestation
 * objects embed public keys in — into a PEM-encoded SubjectPublicKeyInfo
 * that PHP's openssl_* functions can verify signatures against. Supports the
 * two algorithms that matter in practice: ES256 (COSE alg -7, EC2/P-256 —
 * every platform authenticator: Touch ID, Windows Hello, Android biometric,
 * and the large majority of security keys) and RS256 (COSE alg -257 —
 * remaining security keys/authenticators that only offer RSA). Anything
 * else (EdDSA, ES384/512, RS384/512...) is explicitly rejected rather than
 * silently mishandled.
 *
 * DER construction is done by hand (fixed prefixes for the well-known P-256
 * OID; minimal ASN.1 INTEGER/SEQUENCE/BIT STRING encoding for RSA) — no
 * external ASN.1 library exists in this install's vendor tree, and these
 * structures are small, fixed-shape, and directly checkable against known
 * test vectors (see tests/webauthn-format.php).
 */

namespace APP\plugins\generic\magicLogin\classes\webauthn;

class Cose
{
    public const ALG_ES256 = -7;
    public const ALG_RS256 = -257;

    private const KTY_EC2 = 2;
    private const KTY_RSA = 3;
    private const CRV_P256 = 1;

    /**
     * @param array $coseKey Decoded COSE_Key map (integer keys, as produced by Cbor::decode()).
     * @return array{pem: string, alg: int}
     */
    public static function toPem(array $coseKey): array
    {
        $kty = $coseKey[1] ?? null;
        $alg = $coseKey[3] ?? null;

        if ($kty === self::KTY_EC2) {
            if ($alg !== self::ALG_ES256) {
                throw new \RuntimeException('COSE: unsupported EC2 algorithm ' . var_export($alg, true));
            }
            $crv = $coseKey[-1] ?? null;
            $x = $coseKey[-2] ?? null;
            $y = $coseKey[-3] ?? null;
            if ($crv !== self::CRV_P256 || !is_string($x) || !is_string($y) || strlen($x) !== 32 || strlen($y) !== 32) {
                throw new \RuntimeException('COSE: malformed EC2/P-256 key');
            }
            return ['pem' => self::ec256PointToPem($x . $y), 'alg' => self::ALG_ES256];
        }

        if ($kty === self::KTY_RSA) {
            if ($alg !== self::ALG_RS256) {
                throw new \RuntimeException('COSE: unsupported RSA algorithm ' . var_export($alg, true));
            }
            $n = $coseKey[-1] ?? null;
            $e = $coseKey[-2] ?? null;
            if (!is_string($n) || !is_string($e) || strlen($n) < 128) {
                throw new \RuntimeException('COSE: malformed RSA key');
            }
            return ['pem' => self::rsaModulusExponentToPem($n, $e), 'alg' => self::ALG_RS256];
        }

        throw new \RuntimeException('COSE: unsupported key type ' . var_export($kty, true));
    }

    /**
     * Uncompressed P-256 point (64 raw bytes: 32 X + 32 Y) -> PEM SPKI.
     * The DER prefix here is fixed and well-known for id-ecPublicKey +
     * prime256v1 — verified against a real openssl-generated P-256 key's
     * DER output in tests/webauthn-format.php.
     */
    private static function ec256PointToPem(string $point64): string
    {
        if (strlen($point64) !== 64) {
            throw new \RuntimeException('COSE: EC point must be 64 raw bytes');
        }
        // 30 59 30 13 06 07 2a8648ce3d0201 06 08 2a8648ce3d030107 03 42 00 04 <X><Y>
        $prefix = hex2bin('3059301306072a8648ce3d020106082a8648ce3d030107034200');
        $der = $prefix . chr(0x04) . $point64;
        return self::derToPem($der);
    }

    /** RSA (modulus, exponent) -> PEM SPKI (PKCS#1 RSAPublicKey wrapped in an SPKI envelope). */
    private static function rsaModulusExponentToPem(string $n, string $e): string
    {
        $modulus = self::derInteger($n);
        $exponent = self::derInteger($e);
        $rsaPublicKey = self::derSequence($modulus . $exponent);

        $algorithmIdentifier = hex2bin('300d06092a864886f70d0101010500'); // rsaEncryption, NULL params
        $bitString = chr(0x03) . self::derLength(strlen($rsaPublicKey) + 1) . chr(0x00) . $rsaPublicKey;
        $der = self::derSequence($algorithmIdentifier . $bitString);
        return self::derToPem($der);
    }

    /** ASN.1 INTEGER, prefixing a 0x00 byte if the high bit of the first byte would otherwise flip the sign. */
    private static function derInteger(string $bytes): string
    {
        $bytes = ltrim($bytes, "\x00");
        if ($bytes === '' || (ord($bytes[0]) & 0x80) !== 0) {
            $bytes = "\x00" . $bytes;
        }
        return chr(0x02) . self::derLength(strlen($bytes)) . $bytes;
    }

    private static function derSequence(string $contents): string
    {
        return chr(0x30) . self::derLength(strlen($contents)) . $contents;
    }

    private static function derLength(int $length): string
    {
        if ($length < 0x80) {
            return chr($length);
        }
        $bytes = '';
        while ($length > 0) {
            $bytes = chr($length & 0xff) . $bytes;
            $length >>= 8;
        }
        return chr(0x80 | strlen($bytes)) . $bytes;
    }

    private static function derToPem(string $der): string
    {
        return "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END PUBLIC KEY-----\n";
    }
}
