<?php

namespace Jkbennemann\Webauthn\Util;

use Jkbennemann\Webauthn\ByteBuffer;
use Jkbennemann\Webauthn\Exceptions\WebauthnException;

class CborDecoder
{
    public const CBOR_MAJOR_UNSIGNED_INT = 0;
    public const CBOR_MAJOR_TEXT_STRING = 3;
    public const CBOR_MAJOR_FLOAT_SIMPLE = 7;
    public const CBOR_MAJOR_NEGATIVE_INT = 1;
    public const CBOR_MAJOR_ARRAY = 4;
    public const CBOR_MAJOR_TAG = 6;
    public const CBOR_MAJOR_MAP = 5;
    public const CBOR_MAJOR_BYTE_STRING = 2;

    /**
     * @param ByteBuffer|string $bufOrBin
     * @return mixed
     * @throws WebauthnException
     */
    public static function decode($bufOrBin)
    {
        $buf = $bufOrBin instanceof ByteBuffer ? $bufOrBin : new ByteBuffer($bufOrBin);

        $offset = 0;
        $result = self::_parseItem($buf, $offset);
        if ($offset !== $buf->getLength()) {
            throw new WebauthnException('Unused bytes after data item.', WebauthnException::CBOR);
        }

        return $result;
    }

    /**
     * @param ByteBuffer|string $bufOrBin
     * @param int $startOffset
     * @param int|null $endOffset
     * @return mixed
     */
    public static function decodeInPlace($bufOrBin, $startOffset, &$endOffset = null)
    {
        $buf = $bufOrBin instanceof ByteBuffer ? $bufOrBin : new ByteBuffer($bufOrBin);

        $offset = $startOffset;
        $data = self::_parseItem($buf, $offset);
        $endOffset = $offset;

        return $data;
    }

    // ---------------------
    // protected
    // ---------------------

    /**
     * @param ByteBuffer $buf
     * @param int $offset
     * @return mixed
     */
    protected static function _parseItem(ByteBuffer $buf, &$offset)
    {
        $first = $buf->getByteVal($offset++);
        $type = $first >> 5;
        $val = $first & 0b11111;

        if ($type === self::CBOR_MAJOR_FLOAT_SIMPLE) {
            return self::_parseFloatSimple($val, $buf, $offset);
        }

        $val = self::_parseExtraLength($val, $buf, $offset);

        return self::_parseItemData($type, $val, $buf, $offset);
    }

    protected static function _parseFloatSimple($val, ByteBuffer $buf, &$offset)
    {
        switch ($val) {
            case 24:
                $val = $buf->getByteVal($offset);
                $offset++;

                return self::_parseSimple($val);

            case 25:
                $floatValue = $buf->getHalfFloatVal($offset);
                $offset += 2;

                return $floatValue;

            case 26:
                $floatValue = $buf->getFloatVal($offset);
                $offset += 4;

                return $floatValue;

            case 27:
                $floatValue = $buf->getDoubleVal($offset);
                $offset += 8;

                return $floatValue;

            case 28:
            case 29:
            case 30:
                throw new WebauthnException('Reserved value used.', WebauthnException::CBOR);

            case 31:
                throw new WebauthnException('Indefinite length is not supported.', WebauthnException::CBOR);
        }

        return self::_parseSimple($val);
    }

    /**
     * @param int $val
     * @return mixed
     * @throws WebauthnException
     */
    protected static function _parseSimple($val)
    {
        if ($val === 20) {
            return false;
        }
        if ($val === 21) {
            return true;
        }
        if ($val === 22) {
            return null;
        }

        throw new WebauthnException(sprintf('Unsupported simple value %d.', $val), WebauthnException::CBOR);
    }

    protected static function _parseExtraLength($val, ByteBuffer $buf, &$offset)
    {
        switch ($val) {
            case 24:
                $val = $buf->getByteVal($offset);
                $offset++;

                break;

            case 25:
                $val = $buf->getUint16Val($offset);
                $offset += 2;

                break;

            case 26:
                $val = $buf->getUint32Val($offset);
                $offset += 4;

                break;

            case 27:
                $val = $buf->getUint64Val($offset);
                $offset += 8;

                break;

            case 28:
            case 29:
            case 30:
                throw new WebauthnException('Reserved value used.', WebauthnException::CBOR);

            case 31:
                throw new WebauthnException('Indefinite length is not supported.', WebauthnException::CBOR);
        }

        return $val;
    }

    protected static function _parseItemData($type, $val, ByteBuffer $buf, &$offset)
    {
        switch ($type) {
            case self::CBOR_MAJOR_UNSIGNED_INT: // uint
                return $val;

            case self::CBOR_MAJOR_NEGATIVE_INT:
                return -1 - $val;

            case self::CBOR_MAJOR_BYTE_STRING:
                $data = $buf->getBytes($offset, $val);
                $offset += $val;

                return new ByteBuffer($data); // bytes

            case self::CBOR_MAJOR_TEXT_STRING:
                $data = $buf->getBytes($offset, $val);
                $offset += $val;

                return $data; // UTF-8

            case self::CBOR_MAJOR_ARRAY:
                return self::_parseArray($buf, $offset, $val);

            case self::CBOR_MAJOR_MAP:
                return self::_parseMap($buf, $offset, $val);

            case self::CBOR_MAJOR_TAG:
                return self::_parseItem($buf, $offset); // 1 embedded data item
        }

        // This should never be reached
        throw new WebauthnException(sprintf('Unknown major type %d.', $type), WebauthnException::CBOR);
    }

    protected static function _parseMap(ByteBuffer $buf, &$offset, $count)
    {
        $map = [];

        for ($i = 0; $i < $count; $i++) {
            $mapKey = self::_parseItem($buf, $offset);
            $mapVal = self::_parseItem($buf, $offset);

            if (! \is_int($mapKey) && ! \is_string($mapKey)) {
                throw new WebauthnException('Can only use strings or integers as map keys', WebauthnException::CBOR);
            }

            $map[$mapKey] = $mapVal; // todo dup
        }

        return $map;
    }

    protected static function _parseArray(ByteBuffer $buf, &$offset, $count)
    {
        $arr = [];
        for ($i = 0; $i < $count; $i++) {
            $arr[] = self::_parseItem($buf, $offset);
        }

        return $arr;
    }
}
