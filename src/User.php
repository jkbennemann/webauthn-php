<?php

namespace Jkbennemann\Webauthn;

class User
{
    public function __construct(public ByteBuffer $id, public string $name, public string $displayName)
    {
    }
}
