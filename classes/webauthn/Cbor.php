<?php

/**
 * @file classes/webauthn/Cbor.php
 *
 * @class Cbor
 *
 * @brief Minimal CBOR (RFC 8949) decoder — only the subset WebAuthn actually
 * uses: unsigned/negative integers, byte strings, text strings, arrays, maps,
 * and the simple values true/false/null. No indefinite-length items, no
 * tags, no floats beyond what a COSE key needs (none) — anything outside
 * this subset throws rather than silently mis-parsing security-relevant
 * data. Hand-written because no CBOR library exists anywhere in this OJS
 * install's vendor tree (same reasoning as classes/TotpService.php's
 * from-scratch RFC 6238), but unlike TOTP this sits directly in front of a
 * cryptographic signature check, so it fails closed on anything unexpected.
 */

namespace APP\plugins\generic\magicLogin\classes\webauthn;

class Cbor
{
    private string $data;
    private int $offset = 0;

    private function __construct(string $data)
    {
        $this->data = $data;
    }

    /** Decode a single CBOR item from the start of $data. Throws on trailing garbage only if $allowTrailing is false. */
    public static function decode(string $data, bool $allowTrailing = false)
    {
        $decoder = new self($data);
        $value = $decoder->decodeItem();
        if (!$allowTrailing && $decoder->offset !== strlen($data)) {
            throw new \RuntimeException('CBOR: trailing data after top-level item');
        }
        return $value;
    }

    /** Decode one item and return [$value, $bytesConsumed] — for callers that need to know where the item ended (e.g. authData parsing). */
    public static function decodeWithLength(string $data)
    {
        $decoder = new self($data);
        $value = $decoder->decodeItem();
        return [$value, $decoder->offset];
    }

    private function decodeItem()
    {
        $initial = $this->readByte();
        $majorType = $initial >> 5;
        $additional = $initial & 0x1f;

        switch ($majorType) {
            case 0: // unsigned int
                return $this->readLength($additional);
            case 1: // negative int
                return -1 - $this->readLength($additional);
            case 2: // byte string
                return $this->readBytes($this->readLength($additional));
            case 3: // text string
                return $this->readBytes($this->readLength($additional));
            case 4: // array
                $count = $this->readLength($additional);
                $arr = [];
                for ($i = 0; $i < $count; $i++) {
                    $arr[] = $this->decodeItem();
                }
                return $arr;
            case 5: // map
                $count = $this->readLength($additional);
                $map = [];
                for ($i = 0; $i < $count; $i++) {
                    $key = $this->decodeItem();
                    $val = $this->decodeItem();
                    $map[$key] = $val;
                }
                return $map;
            case 7: // simple/float
                if ($additional === 20) {
                    return false;
                }
                if ($additional === 21) {
                    return true;
                }
                if ($additional === 22) {
                    return null;
                }
                throw new \RuntimeException('CBOR: unsupported simple value ' . $additional);
            default:
                throw new \RuntimeException('CBOR: unsupported major type ' . $majorType);
        }
    }

    private function readLength(int $additional): int
    {
        if ($additional < 24) {
            return $additional;
        }
        if ($additional === 24) {
            return $this->readByte();
        }
        if ($additional === 25) {
            return $this->readUint(2);
        }
        if ($additional === 26) {
            return $this->readUint(4);
        }
        if ($additional === 27) {
            $high = $this->readUint(4);
            $low = $this->readUint(4);
            if ($high !== 0) {
                throw new \RuntimeException('CBOR: 64-bit length exceeds PHP int range');
            }
            return $low;
        }
        throw new \RuntimeException('CBOR: indefinite-length items are not supported');
    }

    private function readByte(): int
    {
        if ($this->offset >= strlen($this->data)) {
            throw new \RuntimeException('CBOR: unexpected end of data');
        }
        return ord($this->data[$this->offset++]);
    }

    private function readUint(int $numBytes): int
    {
        $value = 0;
        for ($i = 0; $i < $numBytes; $i++) {
            $value = ($value << 8) | $this->readByte();
        }
        return $value;
    }

    private function readBytes(int $length): string
    {
        if ($length < 0 || $this->offset + $length > strlen($this->data)) {
            throw new \RuntimeException('CBOR: byte/text string length out of bounds');
        }
        $bytes = substr($this->data, $this->offset, $length);
        $this->offset += $length;
        return $bytes;
    }
}
