<?php

namespace Jkbennemann\Webauthn\Attestation\Format;

use Jkbennemann\Webauthn\Attestation\AuthenticatorData;
use Jkbennemann\Webauthn\Exceptions\WebauthnException;

abstract class BaseFormat
{
    protected $_attestationObject = null;
    protected $_authenticatorData = null;
    protected $_x5c_chain = [];
    protected $_x5c_tempFile = null;

    /**
     *
     * @param array $AttestionObject
     * @param AuthenticatorData $authenticatorData
     */
    public function __construct($AttestionObject, AuthenticatorData $authenticatorData)
    {
        $this->_attestationObject = $AttestionObject;
        $this->_authenticatorData = $authenticatorData;
    }

    /**
     *
     */
    public function __destruct()
    {
        // delete X.509 chain certificate file after use
        if ($this->_x5c_tempFile && \is_file($this->_x5c_tempFile)) {
            \unlink($this->_x5c_tempFile);
        }
    }

    /**
     * returns the certificate chain in PEM format
     * @return string|null
     */
    public function getCertificateChain()
    {
        if ($this->_x5c_tempFile && \is_file($this->_x5c_tempFile)) {
            return \file_get_contents($this->_x5c_tempFile);
        }

        return null;
    }

    /**
     * returns the key X.509 certificate in PEM format
     * @return string
     */
    public function getCertificatePem()
    {
        // need to be overwritten
        return null;
    }

    /**
     * checks validity of the signature
     * @param string $clientDataHash
     * @return bool
     * @throws WebauthnException
     */
    public function validateAttestation($clientDataHash)
    {
        // need to be overwritten
        return false;
    }

    /**
     * validates the certificate against root certificates
     * @param array $rootCas
     * @return bool
     * @throws WebauthnException
     */
    public function validateRootCertificate($rootCas)
    {
        // need to be overwritten
        return false;
    }

    /**
     * create a PEM encoded certificate with X.509 binary data
     * @param string $x5c
     * @return string
     */
    protected function _createCertificatePem($x5c)
    {
        $pem = '-----BEGIN CERTIFICATE-----' . "\n";
        $pem .= \chunk_split(\base64_encode($x5c), 64, "\n");
        $pem .= '-----END CERTIFICATE-----' . "\n";

        return $pem;
    }

    /**
     * creates a PEM encoded chain file
     */
    protected function _createX5cChainFile()
    {
        $content = '';
        if (\is_array($this->_x5c_chain) && \count($this->_x5c_chain) > 0) {
            foreach ($this->_x5c_chain as $x5c) {
                $certInfo = \openssl_x509_parse($this->_createCertificatePem($x5c));
                // check if issuer = subject (self signed)
                if (\is_array($certInfo) && \is_array($certInfo['issuer']) && \is_array($certInfo['subject'])) {
                    $selfSigned = true;
                    foreach ($certInfo['issuer'] as $k => $v) {
                        if ($certInfo['subject'][$k] !== $v) {
                            $selfSigned = false;

                            break;
                        }
                    }

                    if (! $selfSigned) {
                        $content .= "\n" . $this->_createCertificatePem($x5c) . "\n";
                    }
                }
            }
        }

        if ($content) {
            $this->_x5c_tempFile = \sys_get_temp_dir() . '/x5c_chain_' . \base_convert(\rand(), 10, 36) . '.pem';
            if (\file_put_contents($this->_x5c_tempFile, $content) !== false) {
                return $this->_x5c_tempFile;
            }
        }

        return null;
    }

    /**
     * returns the name and openssl key for provided cose number.
     * @param int $coseNumber
     * @return \stdClass|null
     */
    protected function _getCoseAlgorithm($coseNumber)
    {
        // https://www.iana.org/assignments/cose/cose.xhtml#algorithms
        $coseAlgorithms = [
            [
                'hash' => 'SHA1',
                'openssl' => OPENSSL_ALGO_SHA1,
                'cose' => [
                    -65535,  // RS1
                ], ],

            [
                'hash' => 'SHA256',
                'openssl' => OPENSSL_ALGO_SHA256,
                'cose' => [
                    -257, // RS256
                    -37,  // PS256
                    -7,   // ES256
                    5,     // HMAC256
                ], ],

            [
                'hash' => 'SHA384',
                'openssl' => OPENSSL_ALGO_SHA384,
                'cose' => [
                    -258, // RS384
                    -38,  // PS384
                    -35,  // ES384
                    6,     // HMAC384
                ], ],

            [
                'hash' => 'SHA512',
                'openssl' => OPENSSL_ALGO_SHA512,
                'cose' => [
                    -259, // RS512
                    -39,  // PS512
                    -36,  // ES512
                    7,     // HMAC512
                ], ],
        ];

        foreach ($coseAlgorithms as $coseAlgorithm) {
            if (\in_array($coseNumber, $coseAlgorithm['cose'], true)) {
                $return = new \stdClass();
                $return->hash = $coseAlgorithm['hash'];
                $return->openssl = $coseAlgorithm['openssl'];

                return $return;
            }
        }

        return null;
    }
}
