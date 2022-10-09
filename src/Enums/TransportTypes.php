<?php

namespace Jkbennemann\Webauthn\Enums;

use ReflectionClass;

class TransportTypes
{
    public const NFC = 'nfc';
    public const BLE = 'ble';
    public const USB = 'usb';
    public const INTERNAL = 'internal';

    public static function all(): array
    {
        $reflection = new ReflectionClass(self::class);

        return $reflection->getConstants();
    }
}
