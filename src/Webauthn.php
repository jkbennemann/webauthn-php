<?php

namespace Jkbennemann\Webauthn;

use function count;
use function hash;
use function in_array;
use function is_object;

use Jkbennemann\Webauthn\Attestation\AttestationObject;

use Jkbennemann\Webauthn\Enums\KeyFormat;
use Jkbennemann\Webauthn\Enums\UserVerification;
use Jkbennemann\Webauthn\Exceptions\WebauthnException;

use function json_decode;
use function preg_match;
use function preg_quote;
use function property_exists;

use stdClass;

class Webauthn
{
    private array $formats = [];
    private ?ByteBuffer $challenge = null;
    private array $certificates = [];
    private int $signatureCounter = 0;
    private ReplyingParty $replyingParty;

    /**
     * @throws WebauthnException
     */
    public function __construct(private Configuration $configuration, null|array $allowedFormats)
    {
        if (! function_exists('\openssl_open')) {
            throw new WebauthnException('OpenSSL module not installed');
        }

        if (! in_array('SHA256', array_map('strtoupper', openssl_get_md_methods()))) {
            throw new WebauthnException('SHA256 is not supported by your openssl version.');
        }

        $this->formats = $this->normalizedFormats($allowedFormats);

        $this->replyingParty = new ReplyingParty($this->configuration->name, $this->configuration->identifier);
    }

    /**
     * @throws WebauthnException
     */
    public function getCreateArgs(
        $userId,
        $userName,
        $userDisplayName,
        string $userVerificationType,
        ?bool $crossPlatformAttachment,
        $excludeCredentialIds = [],
        bool $withoutAttestation = false
    ) {
        $excludeCredentials = [];
        if (is_array($excludeCredentialIds)) {
            foreach ($excludeCredentialIds as $id) {
                $tmp = new UserCredential($id, ['usb', 'ble', 'nfc', 'internal']);
//                $tmp->id = $id instanceof ByteBuffer ? $id : new ByteBuffer($id);  // binary
                $tmp->type = 'public-key';
//                $tmp->transports = array('usb', 'ble', 'nfc', 'internal');

                $excludeCredentials[] = $tmp;
            }
        }

        $attestation = 'indirect';
        if (count($this->certificates)) {
            $attestation = 'direct';
        }

        if ($withoutAttestation) {
            $attestation = 'none';
        }

        $rp = new ReplyingParty($this->configuration->name, $this->configuration->identifier);
        $user = new User(new ByteBuffer($userId), $userName, $userDisplayName);
        ray($userId);
        $authenticatorSelection = new AuthenticatorSelection($userVerificationType, false, $crossPlatformAttachment);
        $publicKey = (new PublicKey())
            ->setUser($user)
            ->setReplyParty($rp)
            ->setAuthenticatorSelection($authenticatorSelection)
            ->setExcludeCredentials($excludeCredentials)
            ->setChallenge($this->createChallenge($this->configuration->challengeLength))
            ->setTimeout($this->configuration->timeout)
            ->setExtensions()
            ->addPublicKeys()
            ->setAttestation($attestation);

        ray("public key", $publicKey);

        return $publicKey;
    }

    /**
     * @throws WebauthnException
     */
    public function getVerifyArgs(
        string $requireUserVerification,
        array $credentialIds = []
    ): PublicKey {
//        // validate User Verification Requirement
//        if (\is_bool($requireUserVerification)) {
//            $requireUserVerification = $requireUserVerification ? 'required' : 'preferred';
//        } else if (\is_string($requireUserVerification) && \in_array(\strtolower($requireUserVerification), ['required', 'preferred', 'discouraged'])) {
//            $requireUserVerification = \strtolower($requireUserVerification);
//        } else {
//            $requireUserVerification = 'preferred';
//        }

        $allowedCredentials = [];
        foreach ($credentialIds as $id) {
            $allowedCredentials[] = new PublicKeyLoginParameter(
                $id instanceof ByteBuffer ? $id : new ByteBuffer($id),
                $this->configuration->allowedTransportTypes,
            );
        }


        return (new PublicKey())
            ->setAllowCredentials($allowedCredentials)
            ->setReplyPartyId($this->replyingParty->id)
            ->setChallenge($this->createChallenge($this->configuration->challengeLength))
            ->setTimeout($this->configuration->timeout)
            ->setUserVerification($requireUserVerification);


//        return new PublicKey(
//            $this->replyingParty,
//            new User('', '', ''),
//            new AuthenticatorSelection($requireUserVerification, false, null),
//            $timeout,
//            $this->createChallenge($this->configuration->challengeLength)->jsonSerialize(),
//            null,
//            $allowedCredentials
//        );

//        $args = new \stdClass();
//        $args->publicKey = new \stdClass();
//        $args->publicKey->timeout = $timeout * 1000; // microseconds
//        $args->publicKey->challenge = $this->_createChallenge();  // binary
//        $args->publicKey->userVerification = $requireUserVerification;
//        $args->publicKey->rpId = $this->replyingParty->id;
//        return $args;
    }

    /**
     * process a create request and returns data to save for future logins
     * @param string $clientDataJSON binary from browser
     * @param string $attestationObject binary from browser
     * @param string|ByteBuffer $challenge binary used challange
     * @param bool $requireUserVerification true, if the device must verify user (e.g. by biometric data or pin)
     * @param bool $requireUserPresent false, if the device must NOT check user presence (e.g. by pressing a button)
     * @param bool $failIfRootMismatch false, if there should be no error thrown if root certificate doesn't match
     * @return stdClass
     * @throws WebauthnException
     */
    public function processCreate(
        $clientDataJSON,
        $attestationObject,
        $challenge,
        $requireUserVerification = false,
        $requireUserPresent = true,
        $failIfRootMismatch = true
    ) {
        $clientDataHash = hash('sha256', $clientDataJSON, true);
        $clientData = json_decode($clientDataJSON);
        $challenge = $challenge instanceof ByteBuffer ? $challenge : new ByteBuffer($challenge);

        // security: https://www.w3.org/TR/webauthn/#registering-a-new-credential

        // 2. Let C, the client data claimed as collected during the credential creation,
        //    be the result of running an implementation-specific JSON parser on JSONtext.
        if (! is_object($clientData)) {
            throw new WebauthnException('invalid client data', WebauthnException::INVALID_DATA);
        }

        // 3. Verify that the value of C.type is webauthn.create.
        if (! property_exists($clientData, 'type') || $clientData->type !== 'webauthn.create') {
            throw new WebauthnException('invalid type', WebauthnException::INVALID_TYPE);
        }

        // 4. Verify that the value of C.challenge matches the challenge that was sent to the authenticator in the create() call.
        if (! property_exists($clientData, 'challenge') || ByteBuffer::fromBase64Url($clientData->challenge)->getBinaryString() !== $challenge->getBinaryString()) {
            throw new WebauthnException('invalid challenge', WebauthnException::INVALID_CHALLENGE);
        }

        // 5. Verify that the value of C.origin matches the Relying Party's origin.
        if (! property_exists($clientData, 'origin') || ! $this->checkOrigin($clientData->origin)) {
            throw new WebauthnException('invalid origin', WebauthnException::INVALID_ORIGIN);
        }

        // Attestation
        $attestationObject = new AttestationObject($attestationObject, $this->formats);

        // 9. Verify that the RP ID hash in authData is indeed the SHA-256 hash of the RP ID expected by the RP.
        if (! $attestationObject->validateRpIdHash($this->replyingParty->hashId())) {
            throw new WebauthnException('invalid rpId hash', WebauthnException::INVALID_RELYING_PARTY);
        }

        // 14. Verify that attStmt is a correct attestation statement, conveying a valid attestation signature
        if (! $attestationObject->validateAttestation($clientDataHash)) {
            throw new WebauthnException('invalid certificate signature', WebauthnException::INVALID_SIGNATURE);
        }

        // 15. If validation is successful, obtain a list of acceptable trust anchors
        $rootValid = count($this->certificates) ? $attestationObject->validateRootCertificate($this->certificates) : null;
        if ($failIfRootMismatch && count($this->certificates) && ! $rootValid) {
            throw new WebauthnException('invalid root certificate', WebauthnException::CERTIFICATE_NOT_TRUSTED);
        }

        // 10. Verify that the User Present bit of the flags in authData is set.
        $userPresent = $attestationObject->getAuthenticatorData()->getUserPresent();
        if ($requireUserPresent && ! $userPresent) {
            throw new WebauthnException('user not present during authentication', WebauthnException::USER_PRESENT);
        }

        // 11. If user verification is required for this registration, verify that the User Verified bit of the flags in authData is set.
        $userVerified = $attestationObject->getAuthenticatorData()->getUserVerified();
        if ($requireUserVerification && ! $userVerified) {
            throw new WebauthnException('user not verified during authentication', WebauthnException::USER_UNVERIFIED);
        }

        $signCount = $attestationObject->getAuthenticatorData()->getSignCount();
        if ($signCount > 0) {
            $this->signatureCounter = $signCount;
        }

        // prepare data to store for future logins
        $data = new stdClass();
        $data->rpId = $this->replyingParty->id;
        $data->attestationFormat = $attestationObject->getAttestationFormatName();
        $data->credentialId = bin2hex($attestationObject->getAuthenticatorData()->getCredentialId());
        $data->credentialPublicKey = $attestationObject->getAuthenticatorData()->getPublicKeyPem();
        $data->certificateChain = $attestationObject->getCertificateChain();
        $data->certificate = $attestationObject->getCertificatePem();
        $data->certificateIssuer = $attestationObject->getCertificateIssuer();
        $data->certificateSubject = $attestationObject->getCertificateSubject();
        $data->signatureCounter = $this->signatureCounter;
        $data->AAGUID = bin2hex($attestationObject->getAuthenticatorData()->getAAGUID());
        $data->rootValid = $rootValid;
        $data->userPresent = $userPresent;
        $data->userVerified = $userVerified;

        return $data;
    }

    private function getChallenge(): string
    {
        return $this->challenge;
    }

    /**
     * @throws WebauthnException
     */
    private function createChallenge(int $length): ByteBuffer
    {
        if (! $this->challenge) {
            $this->challenge = ByteBuffer::randomBuffer($length);
        }

        return $this->challenge;
    }

    private function checkOrigin(string $origin): bool
    {
        // https://www.w3.org/TR/webauthn/#rp-id

        // The origin's scheme must be https and not be ignored/whitelisted
        if (! in_array($this->replyingParty->id, $this->configuration->ignoreOrigins) && parse_url($origin, PHP_URL_SCHEME) !== 'https') {
            return false;
        }

        // extract host from origin
        $host = parse_url($origin, PHP_URL_HOST);
        $host = trim($host, '.');

        // The RP ID must be equal to the origin's effective domain, or a registrable
        // domain suffix of the origin's effective domain.
        return preg_match('/' . preg_quote($this->replyingParty->id) . '$/i', $host) === 1;
    }

    private function normalizedFormats(?array $allowedFormats): array
    {
        $supportedFormats = KeyFormat::all();

        if (! $allowedFormats) {
            return $supportedFormats;
        }

        $desiredFormats = array_filter($allowedFormats, function ($entry) use ($supportedFormats) {
            return in_array($entry, $supportedFormats);
        });

        if (count($desiredFormats) > 0) {
            return $desiredFormats;
        }

        return $supportedFormats;
    }
}
