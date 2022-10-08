<?php

namespace Jkbennemann\Webauthn;

class UserCredential
{
    public string $type = 'public-key';

    public function __construct(public int $id, public array $transportTypes = [])
    {
    }
}
