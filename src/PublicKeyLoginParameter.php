<?php

namespace Jkbennemann\Webauthn;

class PublicKeyLoginParameter
{
    public string $type = 'public-key';

    public function __construct(public ByteBuffer $id, public array $transports = [])
    {
    }
}
