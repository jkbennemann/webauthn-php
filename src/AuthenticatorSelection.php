<?php

namespace Jkbennemann\Webauthn;

class AuthenticatorSelection
{
    public string $residentKeyType;
    public ?string $authenticatorAttachment = 'cross-platform';

    public function __construct(public string $userVerification, public bool $requiresResidentKey, ?bool $crossPlatform)
    {
        if ($requiresResidentKey) {
            $this->residentKeyType = $userVerification;
        }

        if ($crossPlatform === false) {
            $this->authenticatorAttachment = 'platform';
        }

        if (is_null($crossPlatform)) {
            $this->authenticatorAttachment = null;
        }
    }
}
