<?php

namespace Jkbennemann\Webauthn;

use stdClass;

class PublicKey
{
    public int $timeout;
    public array $pubKeyCredParams = [];
    public stdClass $extensions;

    public function __construct(
        public ReplyingParty $rp,
        public User $user,
        public AuthenticatorSelection $authenticatorSelection,
        int $timeout,
        public string $challenge,
        public string $attestation,
        public array $allowedCredentials = [],
        public array $excludeCredentials = [],
    ) {
        $this->timeout = $timeout * 1000;

        $this->pubKeyCredParams[] = new PublicKeyCredentialParameter(-7);
        $this->pubKeyCredParams[] = new PublicKeyCredentialParameter(-257);

        $this->extensions = new stdClass();
        $this->extensions->exts = true;
    }
}
