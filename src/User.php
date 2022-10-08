<?php

namespace Jkbennemann\Webauthn;

class User
{
    public function __construct(public string $id, public string $name, public string $displayName)
    {
    }
}
