<?php

namespace Jkbennemann\Webauthn;

class AuthenticatorSelection
{
    //public string $residentKeyType;
    public ?string $authenticatorAttachment;

    public function __construct(public string $userVerification, public bool $requiresResidentKey, ?bool $crossPlatform = null)
    {
//        if ($requiresResidentKey) {
//            $this->residentKeyType = $userVerification;
//        }

        if ($crossPlatform === true) {
            $this->authenticatorAttachment = 'cross-platform';
        }

        if ($crossPlatform === false) {
            $this->authenticatorAttachment = 'platform';
        }
    }
}
