<?php

namespace Jkbennemann\Webauthn;

use stdClass;

class PublicKey
{
    public int $timeout = 60 * 1000;
    /** @var PublicKeyCredentialParameter[] */
    public array $pubKeyCredParams = [];
    public AuthenticatorSelection $authenticatorSelection;
    public stdClass $extensions;
    public ReplyingParty $rp;
    public User $user;
    public ByteBuffer $challenge;
    public array $excludeCredentials;
    public array $allowCredentials;
    public string $attestation;

    //only for login
    public string $rpId;
    public string $userVerification;

    public function __construct(

    ) {
        $this->pubKeyCredParams[] = new PublicKeyCredentialParameter(-7);
        $this->pubKeyCredParams[] = new PublicKeyCredentialParameter(-257);

        $this->extensions = new stdClass();
        $this->extensions->exts = true;
    }

    public function setReplyParty(ReplyingParty $rp): self
    {
        $this->rp = $rp;

        return $this;
    }

    public function setReplyPartyId(string $rpId): self
    {
        $this->rpId = $rpId;

        return $this;
    }

    public function setUserVerification(string $userVerification): self
    {
        $this->userVerification = $userVerification;

        return $this;
    }

    public function setTimeout(int $timeout): self
    {
        $this->timeout = $timeout * 1000;

        return $this;
    }

    public function setAuthenticatorSelection(AuthenticatorSelection $authenticatorSelection): self
    {
        $this->authenticatorSelection = $authenticatorSelection;

        return $this;
    }

    public function setUser(User $user): self
    {
        $this->user = $user;

        return $this;
    }

    public function setAttestation(string $attestation): self
    {
        $this->attestation = $attestation;

        return $this;
    }

    public function setChallenge(string|ByteBuffer $challenge): self
    {
        if ($challenge instanceof ByteBuffer) {
            $this->challenge = $challenge;
        } else {
            $this->challenge = new ByteBuffer($challenge);
        }

        return $this;
    }

    public function setExcludeCredentials(array $excludeCredentials): self
    {
        $this->excludeCredentials = $excludeCredentials;

        return $this;
    }

    public function setAllowCredentials(array $allowCredentials): self
    {
        $this->allowCredentials = $allowCredentials;

        return $this;
    }
}
