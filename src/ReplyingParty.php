<?php

namespace Jkbennemann\Webauthn;

class ReplyingParty
{
    public function __construct(public string $name, public string $id)
    {
    }

    public function hashId(): string
    {
        return hash('sha256', $this->id, true);
    }
}
