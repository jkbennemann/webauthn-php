<?php

namespace Jkbennemann\Webauthn;

use Jkbennemann\Webauthn\Exceptions\WebauthnException;

class ByteBuffer implements \JsonSerializable, \Serializable
{
    /**
     * @var bool
     */
    public static $useBase64UrlEncoding = false;

    /**
     * @var string
     */
    private $data;

    /**
     * @var int
     */
    private $length;

    public function __construct($binaryData)
    {
        $this->data = (string)$binaryData;
        $this->length = \strlen($binaryData);
    }


    // -----------------------
    // PUBLIC STATIC
    // -----------------------

    /**
     * create a ByteBuffer from a base64 url encoded string
     * @param string $base64url
     * @return ByteBuffer
     */
    public static function fromBase64Url($base64url): ByteBuffer
    {
        $bin = self::_base64url_decode($base64url);
        if ($bin === false) {
            throw new WebauthnException('ByteBuffer: Invalid base64 url string', WebauthnException::BYTEBUFFER);
        }

        return new ByteBuffer($bin);
    }

    /**
     * create a ByteBuffer from a base64 url encoded string
     * @param string $hex
     * @return ByteBuffer
     */
    public static function fromHex($hex): ByteBuffer
    {
        $bin = \hex2bin($hex);
        if ($bin === false) {
            throw new WebauthnException('ByteBuffer: Invalid hex string', WebauthnException::BYTEBUFFER);
        }

        return new ByteBuffer($bin);
    }

    /**
     * create a random ByteBuffer
     * @param string $length
     * @return ByteBuffer
     */
    public static function randomBuffer($length): ByteBuffer
    {
        if (\function_exists('random_bytes')) { // >PHP 7.0
            return new ByteBuffer(\random_bytes($length));
        } elseif (\function_exists('openssl_random_pseudo_bytes')) {
            return new ByteBuffer(\openssl_random_pseudo_bytes($length));
        } else {
            throw new WebauthnException('ByteBuffer: cannot generate random bytes', WebauthnException::BYTEBUFFER);
        }
    }

    // -----------------------
    // PUBLIC
    // -----------------------

    public function getBytes($offset, $length): string
    {
        if ($offset < 0 || $length < 0 || ($offset + $length > $this->length)) {
            throw new WebauthnException('ByteBuffer: Invalid offset or length', WebauthnException::BYTEBUFFER);
        }

        return \substr($this->data, $offset, $length);
    }

    public function getByteVal($offset): int
    {
        if ($offset < 0 || $offset >= $this->length) {
            throw new WebauthnException('ByteBuffer: Invalid offset', WebauthnException::BYTEBUFFER);
        }

        return \ord(\substr($this->data, $offset, 1));
    }

    public function getJson($jsonFlags = 0)
    {
        $data = \json_decode($this->getBinaryString(), null, 512, $jsonFlags);
        if (\json_last_error() !== JSON_ERROR_NONE) {
            throw new WebauthnException(\json_last_error_msg(), WebauthnException::BYTEBUFFER);
        }

        return $data;
    }

    public function getLength(): int
    {
        return $this->length;
    }

    public function getUint16Val($offset)
    {
        if ($offset < 0 || ($offset + 2) > $this->length) {
            throw new WebauthnException('ByteBuffer: Invalid offset', WebauthnException::BYTEBUFFER);
        }

        return unpack('n', $this->data, $offset)[1];
    }

    public function getUint32Val($offset)
    {
        if ($offset < 0 || ($offset + 4) > $this->length) {
            throw new WebauthnException('ByteBuffer: Invalid offset', WebauthnException::BYTEBUFFER);
        }
        $val = unpack('N', $this->data, $offset)[1];

        // Signed integer overflow causes signed negative numbers
        if ($val < 0) {
            throw new WebauthnException('ByteBuffer: Value out of integer range.', WebauthnException::BYTEBUFFER);
        }

        return $val;
    }

    public function getUint64Val($offset)
    {
        if (PHP_INT_SIZE < 8) {
            throw new WebauthnException('ByteBuffer: 64-bit values not supported by this system', WebauthnException::BYTEBUFFER);
        }
        if ($offset < 0 || ($offset + 8) > $this->length) {
            throw new WebauthnException('ByteBuffer: Invalid offset', WebauthnException::BYTEBUFFER);
        }
        $val = unpack('J', $this->data, $offset)[1];

        // Signed integer overflow causes signed negative numbers
        if ($val < 0) {
            throw new WebauthnException('ByteBuffer: Value out of integer range.', WebauthnException::BYTEBUFFER);
        }

        return $val;
    }

    public function getHalfFloatVal($offset)
    {
        //FROM spec pseudo decode_half(unsigned char *halfp)
        $half = $this->getUint16Val($offset);

        $exp = ($half >> 10) & 0x1f;
        $mant = $half & 0x3ff;

        if ($exp === 0) {
            $val = $mant * (2 ** -24);
        } elseif ($exp !== 31) {
            $val = ($mant + 1024) * (2 ** ($exp - 25));
        } else {
            $val = ($mant === 0) ? INF : NAN;
        }

        return ($half & 0x8000) ? -$val : $val;
    }

    public function getFloatVal($offset)
    {
        if ($offset < 0 || ($offset + 4) > $this->length) {
            throw new WebauthnException('ByteBuffer: Invalid offset', WebauthnException::BYTEBUFFER);
        }

        return unpack('G', $this->data, $offset)[1];
    }

    public function getDoubleVal($offset)
    {
        if ($offset < 0 || ($offset + 8) > $this->length) {
            throw new WebauthnException('ByteBuffer: Invalid offset', WebauthnException::BYTEBUFFER);
        }

        return unpack('E', $this->data, $offset)[1];
    }

    /**
     * @return string
     */
    public function getBinaryString(): string
    {
        return $this->data;
    }

    /**
     * @param string $buffer
     * @return bool
     */
    public function equals($buffer): bool
    {
        return is_string($this->data) && $this->data === $buffer->data;
    }

    /**
     * @return string
     */
    public function getHex(): string
    {
        return \bin2hex($this->data);
    }

    /**
     * @return bool
     */
    public function isEmpty(): bool
    {
        return $this->length === 0;
    }

    /**
     * jsonSerialize interface
     * return binary data in RFC 1342-Like serialized string
     * @return string
     */
    public function jsonSerialize(): string
    {
        if (ByteBuffer::$useBase64UrlEncoding) {
            return self::_base64url_encode($this->data);
        } else {
            return '=?BINARY?B?' . \base64_encode($this->data) . '?=';
        }
    }

    /**
     * Serializable-Interface
     * @return string
     */
    public function serialize(): string
    {
        return \serialize($this->data);
    }

    /**
     * Serializable-Interface
     * @param string $serialized
     */
    public function unserialize($serialized)
    {
        $this->data = \unserialize($serialized);
        $this->length = \strlen($this->data);
    }

    /**
     * (PHP 8 deprecates Serializable-Interface)
     * @return array
     */
    public function __serialize(): array
    {
        return [
            'data' => \serialize($this->data),
        ];
    }

    /**
     * object to string
     * @return string
     */
    public function __toString(): string
    {
        return $this->getHex();
    }

    /**
     * (PHP 8 deprecates Serializable-Interface)
     * @param array $data
     * @return void
     */
    public function __unserialize($data)
    {
        if ($data && isset($data['data'])) {
            $this->data = \unserialize($data['data']);
            $this->length = \strlen($this->data);
        }
    }

    // -----------------------
    // PROTECTED STATIC
    // -----------------------

    /**
     * base64 url decoding
     * @param string $data
     * @return string
     */
    protected static function _base64url_decode($data): string|false
    {
        return \base64_decode(\strtr($data, '-_', '+/') . \str_repeat('=', 3 - (3 + \strlen($data)) % 4));
    }

    /**
     * base64 url encoding
     * @param string $data
     * @return string
     */
    protected static function _base64url_encode($data): string
    {
        return \rtrim(\strtr(\base64_encode($data), '+/', '-_'), '=');
    }
}
