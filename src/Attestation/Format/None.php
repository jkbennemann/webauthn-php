<?php

namespace Jkbennemann\Webauthn\Attestation\Format;

use Jkbennemann\Webauthn\Attestation\AuthenticatorData;

class None extends BaseFormat
{
    public function __construct($AttestionObject, AuthenticatorData $authenticatorData)
    {
        parent::__construct($AttestionObject, $authenticatorData);
    }

    /*
     * returns the key certificate in PEM format
     * @return string
     */
    public function getCertificatePem()
    {
        return null;
    }

    /**
     * @param string $clientDataHash
     */
    public function validateAttestation($clientDataHash)
    {
        return true;
    }

    /**
     * validates the certificate against root certificates.
     * Format 'none' does not contain any ca, so always false.
     * @param array $rootCas
     * @return bool
     */
    public function validateRootCertificate($rootCas)
    {
        return false;
    }
}
