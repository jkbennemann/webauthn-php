<?php

namespace Jkbennemann\Webauthn\Enums;

use ReflectionClass;

class KeyFormat
{
    public const ANDROID_KEY = 'android-key';
    public const ANDROID_SAFETYNET = 'android-safetynet';
    public const APPLE = 'apple';
    public const FIDO_U2FA = 'fido-u2fa';
    public const NONE = 'none';
    public const PACKED = 'packed';
    public const TPM = 'tpm';

    public static function all(): array
    {
        $reflection = new ReflectionClass(self::class);

        return $reflection->getConstants();
    }
}
