<?php

namespace Jkbennemann\Webauthn;

use function count;
use function hash;
use function in_array;
use function is_object;

use Jkbennemann\Webauthn\Attestation\AttestationObject;

use Jkbennemann\Webauthn\Enums\KeyFormat;
use Jkbennemann\Webauthn\Exceptions\WebauthnException;

use function json_decode;
use function openssl_verify;
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
    ): PublicKey {
        $excludeCredentials = [];
        if (is_array($excludeCredentialIds)) {
            foreach ($excludeCredentialIds as $id) {
                $excludeCredentials[] = new UserCredential(
                    new ByteBuffer(hex2bin($id)),
                    ['usb', 'ble', 'nfc', 'internal']
                );
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

        return $publicKey;
    }

    /**
     * @throws WebauthnException
     */
    public function getVerifyArgs(
        string $requireUserVerification,
        array $credentialIds = []
    ): PublicKey {
        $allowedCredentials = [];
        foreach ($credentialIds as $id) {
            $allowedCredentials[] = new PublicKeyLoginParameter(
                new ByteBuffer(hex2bin($id)),
                $this->configuration->allowedTransportTypes,
            );
        }

        return (new PublicKey())
            ->setAllowCredentials($allowedCredentials)
            ->setReplyPartyId($this->replyingParty->id)
            ->setChallenge($this->createChallenge($this->configuration->challengeLength))
            ->setTimeout($this->configuration->timeout)
            ->setUserVerification($requireUserVerification);
    }

    /**
     * @throws WebauthnException
     */
    public function processCreate(
        string $clientDataJSON,
        string $attestationObject,
        string $challenge,
        bool $requireUserVerification = false,
        bool $requireUserPresent = true,
        bool $failIfRootMismatch = true
    ): stdClass {
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

        // 5. Verify that the value of C.origin matches the Replying Party's origin.
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
        $data->credentialPublicKey = json_encode($attestationObject->getAuthenticatorData()->getPublicKeyPem());
        $data->certificateChain = json_encode($attestationObject->getCertificateChain());
        $data->certificate = json_encode($attestationObject->getCertificatePem());
        $data->certificateIssuer = $attestationObject->getCertificateIssuer();
        $data->certificateSubject = $attestationObject->getCertificateSubject();
        $data->signatureCounter = $this->signatureCounter;
        $data->AAGUID = bin2hex($attestationObject->getAuthenticatorData()->getAAGUID());
        $data->rootValid = $rootValid;
        $data->userPresent = $userPresent;
        $data->userVerified = $userVerified;

        return $data;
    }

    /**
     * @throws WebauthnException
     */
    public function processGet(
        $clientDataJSON,
        $authenticatorData,
        $signature,
        $credentialPublicKey,
        $challenge,
        $prevSignatureCnt = null,
        $requireUserVerification = false,
        $requireUserPresent = true
    ): bool {
        $authenticatorObj = new Attestation\AuthenticatorData($authenticatorData);
        $clientDataHash = hash('sha256', $clientDataJSON, true);
        $clientData = json_decode($clientDataJSON);
        $challenge = new ByteBuffer($challenge);

        // https://www.w3.org/TR/webauthn/#verifying-assertion

        // 1. If the allowCredentials option was given when this authentication ceremony was initiated,
        //    verify that credential.id identifies one of the public key credentials that were listed in allowCredentials.
        //    -> TO BE VERIFIED BY IMPLEMENTATION

        // 2. If credential.response.userHandle is present, verify that the user identified
        //    by this value is the owner of the public key credential identified by credential.id.
        //    -> TO BE VERIFIED BY IMPLEMENTATION

        // 3. Using credential’s id attribute (or the corresponding rawId, if base64url encoding is
        //    inappropriate for your use case), look up the corresponding credential public key.
        //    -> TO BE LOOKED UP BY IMPLEMENTATION

        // 5. Let JSON text be the result of running UTF-8 decode on the value of cData.
        if (! is_object($clientData)) {
            throw new WebauthnException('invalid client data', WebauthnException::INVALID_DATA);
        }

        // 7. Verify that the value of C.type is the string webauthn.get.
        if (! property_exists($clientData, 'type') || $clientData->type !== 'webauthn.get') {
            throw new WebauthnException('invalid type', WebauthnException::INVALID_TYPE);
        }

        // 8. Verify that the value of C.challenge matches the challenge that was sent to the
        //    authenticator in the PublicKeyCredentialRequestOptions passed to the get() call.
        if (! property_exists($clientData, 'challenge') || ByteBuffer::fromBase64Url($clientData->challenge)->getBinaryString() !== $challenge->getBinaryString()) {
            throw new WebauthnException('invalid challenge', WebauthnException::INVALID_CHALLENGE);
        }

        // 9. Verify that the value of C.origin matches the Replying Party's origin.
        if (! property_exists($clientData, 'origin') || ! $this->checkOrigin($clientData->origin)) {
            throw new WebauthnException('invalid origin', WebauthnException::INVALID_ORIGIN);
        }

        // 11. Verify that the rpIdHash in authData is the SHA-256 hash of the RP ID expected by the Replying Party.
        if ($authenticatorObj->getRpIdHash() !== $this->replyingParty->hashId()) {
            throw new WebauthnException('invalid rpId hash', WebauthnException::INVALID_RELYING_PARTY);
        }

        // 12. Verify that the User Present bit of the flags in authData is set
        if ($requireUserPresent && ! $authenticatorObj->getUserPresent()) {
            throw new WebauthnException('user not present during authentication', WebauthnException::USER_PRESENT);
        }

        // 13. If user verification is required for this assertion, verify that the User Verified bit of the flags in authData is set.
        if ($requireUserVerification && ! $authenticatorObj->getUserVerified()) {
            throw new WebauthnException('user not verified during authentication', WebauthnException::USER_UNVERIFIED);
        }

        // 14. Verify the values of the client extension outputs
        //     (extensions not implemented)

        // 16. Using the credential public key looked up in step 3, verify that sig is a valid signature
        //     over the binary concatenation of authData and hash.
        $dataToVerify = '';
        $dataToVerify .= $authenticatorData;
        $dataToVerify .= $clientDataHash;

        $publicKey = openssl_pkey_get_public($credentialPublicKey);
        if ($publicKey === false) {
            throw new WebauthnException('public key invalid', WebauthnException::INVALID_PUBLIC_KEY);
        }

        if (openssl_verify($dataToVerify, $signature, $publicKey, OPENSSL_ALGO_SHA256) !== 1) {
            throw new WebauthnException('invalid signature', WebauthnException::INVALID_SIGNATURE);
        }

        $signatureCounter = $authenticatorObj->getSignCount();
        if ($signatureCounter !== 0) {
            $this->signatureCounter = $signatureCounter;
        }

        // 17. If either of the signature counter value authData.signCount or
        //     previous signature count is nonzero, and if authData.signCount
        //     less than or equal to previous signature count, it's a signal
        //     that the authenticator may be cloned
        if ($prevSignatureCnt !== null) {
            if ($signatureCounter !== 0 || $prevSignatureCnt !== 0) {
                if ($prevSignatureCnt >= $signatureCounter) {
                    throw new WebauthnException('signature counter not valid', WebauthnException::SIGNATURE_COUNTER);
                }
            }
        }

        return true;
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
