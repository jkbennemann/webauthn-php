<?php

namespace Jkbennemann\Webauthn;

class AuthenticatorSelection
{
    public string $residentKeyType;
    public string $authenticatorAttachment = 'cross-platform';

    public function __construct(public string $verificationType, public bool $requiresResidentKey, public bool $crossPlatform)
    {
        if ($this->requiresResidentKey) {
            $this->residentKeyType = $this->verificationType;
        }

        if (! $this->crossPlatform) {
            $this->authenticatorAttachment = 'platform';
        }
    }
}
