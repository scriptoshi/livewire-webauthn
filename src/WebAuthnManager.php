<?php

namespace Scriptoshi\LivewireWebauthn;

use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Log;
use Illuminate\Contracts\Auth\Authenticatable;
use Ramsey\Uuid\Uuid;
use Symfony\Component\Serializer\Encoder\JsonEncode;
use Symfony\Component\Serializer\Normalizer\AbstractObjectNormalizer;
use Cose\Algorithm\Manager as CoseAlgorithmManager;
use Cose\Algorithm\Signature\ECDSA\ES256;
use Cose\Algorithm\Signature\ECDSA\ES384;
use Cose\Algorithm\Signature\EdDSA\EdDSA;
use Cose\Algorithm\Signature\RSA\RS256;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AttestationStatement\NoneAttestationStatementSupport;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\CeremonyStep\CeremonyStepManagerFactory;
use Webauthn\Denormalizer\WebauthnSerializerFactory;
use Webauthn\Exception\WebauthnException;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialParameters;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;
use Scriptoshi\LivewireWebauthn\Repository\WebAuthnCredentialRepository;

class WebAuthnManager
{
    /**
     * @var CoseAlgorithmManager
     */
    private $coseAlgorithmManager;

    /**
     * @var WebAuthnCredentialRepository
     */
    private $credentialRepository;

    /**
     * @var \Symfony\Component\Serializer\SerializerInterface
     */
    private $serializer;

    /**
     * @var CeremonyStepManagerFactory
     */
    private $csmFactory;

    /**
     * @var object
     */
    private $creationCsm;

    /**
     * @var object
     */
    private $requestCsm;

    /**
     * WebAuthnManager constructor.
     */
    public function __construct(WebAuthnCredentialRepository $credentialRepository)
    {
        $this->credentialRepository = $credentialRepository;

        // Set up the COSE Algorithm Manager with recommended algorithms
        $this->coseAlgorithmManager = new CoseAlgorithmManager();
        $this->coseAlgorithmManager->add(new ES256());
        $this->coseAlgorithmManager->add(new ES384());
        $this->coseAlgorithmManager->add(new RS256());
        $this->coseAlgorithmManager->add(new EdDSA());

        // Set up the Attestation Statement Support Manager
        $attestationStatementSupportManager = AttestationStatementSupportManager::create();
        $attestationStatementSupportManager->add(NoneAttestationStatementSupport::create());

        // Set up the serializer
        $factory = new WebauthnSerializerFactory($attestationStatementSupportManager);
        $this->serializer = $factory->create();

        // Set up the Ceremony Step Manager Factory
        $this->csmFactory = new CeremonyStepManagerFactory();
        $this->csmFactory->setAlgorithmManager($this->coseAlgorithmManager);

        // Setup the ceremony step managers
        $this->creationCsm = $this->csmFactory->creationCeremony();
        $this->requestCsm = $this->csmFactory->requestCeremony();
    }

    /**
     * Get the Relying Party Entity
     *
     * @return PublicKeyCredentialRpEntity
     */
    public function getRelyingParty(): PublicKeyCredentialRpEntity
    {
        return PublicKeyCredentialRpEntity::create(
            Config::get('webauthn.relying_party.name'),
            Config::get('webauthn.relying_party.id')
        );
    }

    /**
     * Create a user entity for WebAuthn
     *
     * @param Authenticatable $user
     * @return PublicKeyCredentialUserEntity
     */
    public function getUserEntity(Authenticatable $user): PublicKeyCredentialUserEntity
    {
        // The user handle should be a random string that uniquely identifies the user
        // We'll use the user's ID converted to a UUID for this purpose
        $userHandle = Uuid::uuid5(Uuid::NAMESPACE_OID, $user->getAuthIdentifier())->toString();

        return PublicKeyCredentialUserEntity::create(
            $user->email,
            $userHandle,
            $user->name
        );
    }

    /**
     * Generate registration options for creating a new credential
     *
     * @param Authenticatable $user
     * @param string|null $attestation
     * @return array
     */
    public function generateRegistrationOptions(Authenticatable $user, ?string $attestation = null): array
    {
        // Get existing credentials to exclude
        $excludeCredentials = [];

        foreach ($user->webauthnCredentials as $credential) {
            $excludeCredentials[] = PublicKeyCredentialDescriptor::create(
                'public-key',
                base64_decode($credential->credential_id)
            );
        }

        // Create the credential parameters (supported algorithms)
        $pubKeyCredParams = [];
        foreach (Config::get('webauthn.algorithms', [-7, -257, -8]) as $alg) {
            $pubKeyCredParams[] = PublicKeyCredentialParameters::create('public-key', $alg);
        }

        // Set authenticator selection criteria
        $authenticatorSelection = AuthenticatorSelectionCriteria::create(
            Config::get('webauthn.authenticator_attachment', null),
            Config::get('webauthn.resident_key', AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_PREFERRED),
            Config::get('webauthn.user_verification', AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_PREFERRED)
        );

        // Set attestation conveyance preference if provided
        if ($attestation === null) {
            $attestation = Config::get('webauthn.attestation_conveyance', PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE);
        }

        // Create options with all parameters at once
        $options = PublicKeyCredentialCreationOptions::create(
            $this->getRelyingParty(),
            $this->getUserEntity($user),
            random_bytes(32), // Challenge
            $pubKeyCredParams,
            $authenticatorSelection,
            $attestation,
            $excludeCredentials
        );

        // Convert to array for JSON serialization
        return $this->serializeToArray($options);
    }

    /**
     * Verify registration response and save the credential
     *
     * @param string $clientResponse
     * @param array $publicKeyCredentialCreationOptions
     * @param Authenticatable $user
     * @param string|null $credentialName
     * @return bool
     */
    public function verifyRegistrationResponse(
        string $clientResponse,
        array $publicKeyCredentialCreationOptions,
        Authenticatable $user,
        ?string $credentialName = null
    ): bool {
        try {
            // Parse the client response
            $publicKeyCredential = $this->deserialize($clientResponse, PublicKeyCredential::class);

            // Ensure it's an attestation response for registration
            $attestationResponse = $publicKeyCredential->response;
            if (!$attestationResponse instanceof AuthenticatorAttestationResponse) {
                throw new WebauthnException('Invalid response type');
            }

            // Reconstruct the creation options
            $options = $this->deserialize(
                json_encode($publicKeyCredentialCreationOptions),
                PublicKeyCredentialCreationOptions::class
            );

            // Create the validator
            $validator = AuthenticatorAttestationResponseValidator::create($this->creationCsm);

            // Get the expected origin
            $expectedOrigin = Config::get('app.url');

            // Get the expected RP ID
            $expectedRpId = Config::get('webauthn.relying_party.id');

            // Validate the response
            $publicKeyCredentialSource = $validator->check(
                $attestationResponse,
                $options,
                $expectedOrigin,
                $expectedRpId
            );

            // Store the new credential
            $this->credentialRepository->saveCredentialSource($publicKeyCredentialSource, $user->getAuthIdentifier(), $credentialName);

            // Mark WebAuthn as enabled for the user
            $user->webauthn_enabled = true;
            $user->webauthn_confirmed_at = now();
            $user->save();

            return true;
        } catch (\Exception $e) {
            Log::error('WebAuthn registration failed: ' . $e->getMessage(), [
                'trace' => $e->getTraceAsString(),
            ]);
            return false;
        }
    }

    /**
     * Generate authentication options for an existing credential
     *
     * @param Authenticatable|null $user
     * @return array
     */
    public function generateAuthenticationOptions(Authenticatable $user = null): array
    {
        // Create a new challenge
        $challenge = random_bytes(32);

        // Get credentials if user is provided
        $allowCredentials = [];
        if ($user) {
            foreach ($user->webauthnCredentials as $credential) {
                $allowCredentials[] = PublicKeyCredentialDescriptor::create(
                    'public-key',
                    base64_decode($credential->credential_id)
                );
            }
        }

        // Create options with all parameters at once
        $options = PublicKeyCredentialRequestOptions::create(
            $challenge,
            Config::get('webauthn.relying_party.id'),
            $allowCredentials,
            Config::get('webauthn.user_verification', PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_PREFERRED)
        );

        // Convert to array for JSON serialization
        return $this->serializeToArray($options);
    }

    /**
     * Verify authentication response
     *
     * @param string $clientResponse
     * @param array $publicKeyCredentialRequestOptions
     * @param Authenticatable|null $user
     * @return bool|Authenticatable
     */
    public function verifyAuthenticationResponse(
        string $clientResponse,
        array $publicKeyCredentialRequestOptions,
        Authenticatable $user = null
    ) {
        try {
            // Parse the client response
            $publicKeyCredential = $this->deserialize($clientResponse, PublicKeyCredential::class);

            // Ensure it's an assertion response
            $assertionResponse = $publicKeyCredential->response;
            if (!$assertionResponse instanceof AuthenticatorAssertionResponse) {
                throw new WebauthnException('Invalid response type');
            }

            // Get the raw credential ID
            $credentialId = $publicKeyCredential->rawId;

            // Find the credential in our repository
            $publicKeyCredentialSource = $this->credentialRepository->findOneByCredentialId($credentialId);
            if (!$publicKeyCredentialSource) {
                throw new WebauthnException('Unknown credential');
            }

            // Check if the credential belongs to the specified user (if provided)
            if ($user) {
                $publicKeyCredentialUserEntity = $this->credentialRepository->getUserEntityByCredentialSource($publicKeyCredentialSource);
                $expectedUserHandle = $this->getUserEntity($user)->id;

                if ($publicKeyCredentialUserEntity->id !== $expectedUserHandle) {
                    throw new WebauthnException('Credential does not belong to the specified user');
                }
            }

            // Reconstruct the request options
            $options = $this->deserialize(
                json_encode($publicKeyCredentialRequestOptions),
                PublicKeyCredentialRequestOptions::class
            );

            // Get the expected origin
            $expectedOrigin = Config::get('app.url');

            // Create the validator
            $validator = AuthenticatorAssertionResponseValidator::create($this->requestCsm);

            // Validate the response
            $validator->check(
                $publicKeyCredentialSource,
                $assertionResponse,
                $options,
                $expectedOrigin,
                Config::get('webauthn.relying_party.id')
            );

            // Update the credential (last used timestamp)
            $userId = $this->credentialRepository->getUserIdByCredentialSource($publicKeyCredentialSource);
            $this->credentialRepository->updateCredentialLastUsed($credentialId, $userId);

            // Return the user
            if (!$user) {
                $userModel = config('auth.providers.users.model');
                $user = $userModel::find($userId);
            }

            return $user;
        } catch (\Exception $e) {
            Log::error('WebAuthn authentication failed: ' . $e->getMessage(), [
                'trace' => $e->getTraceAsString(),
            ]);
            return false;
        }
    }

    /**
     * Serialize an object to an array
     *
     * @param object $object
     * @return array
     */
    private function serializeToArray($object): array
    {
        $json = $this->serializer->serialize(
            $object,
            'json',
            [
                AbstractObjectNormalizer::SKIP_NULL_VALUES => true,
                JsonEncode::OPTIONS => JSON_THROW_ON_ERROR,
            ]
        );

        return json_decode($json, true);
    }

    /**
     * Deserialize a JSON string to an object
     *
     * @param string $json
     * @param string $type
     * @return object
     */
    private function deserialize(string $json, string $type)
    {
        return $this->serializer->deserialize($json, $type, 'json');
    }
}
