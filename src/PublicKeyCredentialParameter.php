<?php

namespace Jkbennemann\Webauthn;

class PublicKeyCredentialParameter
{
    public string $type = 'public-key';

    public function __construct(public int $alg)
    {
    }
}
