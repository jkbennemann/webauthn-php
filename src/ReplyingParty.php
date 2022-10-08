<?php

namespace Jkbennemann\Webauthn;

use Jkbennemann\Webauthn\Exceptions\WebauthnException;

class ReplyingParty
{
    public string $idHash;

    /**
     * @throws WebauthnException
     */
    public function __construct(public string $name, public string $id)
    {
    }

    private function hastId(): string
    {
        $this->idHash = hash('sha256', $this->id, true);
    }
}
