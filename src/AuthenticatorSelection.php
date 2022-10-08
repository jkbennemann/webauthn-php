<?php

namespace Jkbennemann\Webauthn;

class AuthenticatorSelection
{
    public string $residentKeyType;
    public string $authenticatorAttachment = 'cross-platform';

    public function __construct(public string $userVerification, public bool $requiresResidentKey, public bool $crossPlatform)
    {
        if ($this->requiresResidentKey) {
            $this->residentKeyType = $userVerification;
        }

        if (! $this->crossPlatform) {
            $this->authenticatorAttachment = 'platform';
        }
    }
}
