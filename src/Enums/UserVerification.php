<?php

namespace Jkbennemann\Webauthn\Enums;

use ReflectionClass;

class UserVerification
{
    public const REQUIRED = 'required';
    public const PREFERRED = 'preferred';
    public const DISCOURAGED = 'discouraged';

    public static function all(): array
    {
        $reflection = new ReflectionClass(self::class);

        return $reflection->getConstants();
    }
}
