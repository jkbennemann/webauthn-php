<?php

namespace Jkbennemann\Webauthn;

class Configuration
{
    public const DEFAULT_ORIGINS = [
        'localhost',
    ];

    public function __construct(
        public string $name,
        public string $identifier,
        public int $challengeLength = 32,
        public int $timeout = 5,
        public array $ignoreOrigins = self::DEFAULT_ORIGINS
    ) {
    }
}
