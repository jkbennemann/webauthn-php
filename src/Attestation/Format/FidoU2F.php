<?php

namespace Jkbennemann\Webauthn\Attestation\Format;

use Jkbennemann\Webauthn\Attestation\AuthenticatorData;
use Jkbennemann\Webauthn\ByteBuffer;
use Jkbennemann\Webauthn\Exceptions\WebauthnException;

class FidoU2F extends BaseFormat
{
    private $_alg = -7;
    private $_signature;
    private $_x5c;

    public function __construct($AttestionObject, AuthenticatorData $authenticatorData) {
        parent::__construct($AttestionObject, $authenticatorData);

        // check u2f data
        $attStmt = $this->_attestationObject['attStmt'];

        if (\array_key_exists('alg', $attStmt) && $attStmt['alg'] !== $this->_alg) {
            throw new WebauthnException('u2f only accepts algorithm -7 ("ES256"), but got ' . $attStmt['alg'], WebauthnException::INVALID_DATA);
        }

        if (!\array_key_exists('sig', $attStmt) || !\is_object($attStmt['sig']) || !($attStmt['sig'] instanceof ByteBuffer)) {
            throw new WebauthnException('no signature found', WebauthnException::INVALID_DATA);
        }

        if (!\array_key_exists('x5c', $attStmt) || !\is_array($attStmt['x5c']) || \count($attStmt['x5c']) !== 1) {
            throw new WebauthnException('invalid x5c certificate', WebauthnException::INVALID_DATA);
        }

        if (!\is_object($attStmt['x5c'][0]) || !($attStmt['x5c'][0] instanceof ByteBuffer)) {
            throw new WebauthnException('invalid x5c certificate', WebauthnException::INVALID_DATA);
        }

        $this->_signature = $attStmt['sig']->getBinaryString();
        $this->_x5c = $attStmt['x5c'][0]->getBinaryString();
    }


    /*
     * returns the key certificate in PEM format
     * @return string
     */
    public function getCertificatePem() {
        $pem = '-----BEGIN CERTIFICATE-----' . "\n";
        $pem .= \chunk_split(\base64_encode($this->_x5c), 64, "\n");
        $pem .= '-----END CERTIFICATE-----' . "\n";
        return $pem;
    }

    /**
     * @param string $clientDataHash
     */
    public function validateAttestation($clientDataHash) {
        $publicKey = \openssl_pkey_get_public($this->getCertificatePem());

        if ($publicKey === false) {
            throw new WebauthnException('invalid public key: ' . \openssl_error_string(), WebauthnException::INVALID_PUBLIC_KEY);
        }

        // Let verificationData be the concatenation of (0x00 || rpIdHash || clientDataHash || credentialId || publicKeyU2F)
        $dataToVerify = "\x00";
        $dataToVerify .= $this->_authenticatorData->getRpIdHash();
        $dataToVerify .= $clientDataHash;
        $dataToVerify .= $this->_authenticatorData->getCredentialId();
        $dataToVerify .= $this->_authenticatorData->getPublicKeyU2F();

        $coseAlgorithm = $this->_getCoseAlgorithm($this->_alg);

        // check certificate
        return \openssl_verify($dataToVerify, $this->_signature, $publicKey, $coseAlgorithm->openssl) === 1;
    }

    /**
     * validates the certificate against root certificates
     * @param array $rootCas
     * @return boolean
     * @throws WebauthnException
     */
    public function validateRootCertificate($rootCas) {
        $chainC = $this->_createX5cChainFile();
        if ($chainC) {
            $rootCas[] = $chainC;
        }

        $v = \openssl_x509_checkpurpose($this->getCertificatePem(), -1, $rootCas);
        if ($v === -1) {
            throw new WebauthnException('error on validating root certificate: ' . \openssl_error_string(), WebauthnException::CERTIFICATE_NOT_TRUSTED);
        }
        return $v;
    }
}
