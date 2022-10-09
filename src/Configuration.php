<?php

namespace Jkbennemann\Webauthn;

use Jkbennemann\Webauthn\Enums\TransportTypes;

class Configuration
{
    public const DEFAULT_ORIGINS = [
        'localhost',
    ];

    public const DEFAULT_TRANSPORT_TYPES = [
        TransportTypes::USB,
        TransportTypes::NFC,
        TransportTypes::BLE,
        TransportTypes::INTERNAL,
    ];

    public function __construct(
        public string $name,
        public string $identifier,
        public int $challengeLength = 32,
        public int $timeout = 5,
        public array $ignoreOrigins = self::DEFAULT_ORIGINS,
        public array $allowedTransportTypes = self::DEFAULT_TRANSPORT_TYPES
    ) {
    }
}
