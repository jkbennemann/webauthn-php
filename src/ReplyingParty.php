<?php

namespace Jkbennemann\Webauthn;

class ReplyingParty
{
    public string $idHash;

    public function __construct(public string $name, public string $id)
    {
        $this->idHash = $this->hashId();
    }

    private function hashId(): string
    {
        return hash('sha256', $this->id, true);
    }
}
