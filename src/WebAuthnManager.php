<?php

namespace Scriptoshi\LivewireWebauthn;

use Cose\Algorithm\Manager as CoseAlgorithmManager;
use Cose\Algorithm\Signature\ECDSA\ES256;
use Cose\Algorithm\Signature\ECDSA\ES384;
use Cose\Algorithm\Signature\EdDSA\EdDSA;
use Cose\Algorithm\Signature\RSA\RS256;
use Illuminate\Support\Facades\Config;
use Illuminate\Contracts\Auth\Authenticatable;
use Ramsey\Uuid\Uuid;
use Webauthn\AttestationStatement\AttestationObjectLoader;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AttestationStatement\NoneAttestationStatementSupport;
use Webauthn\AttestationStatement\PackedAttestationStatementSupport;
use Webauthn\AttestationStatement\TPMAttestationStatementSupport;
use Webauthn\AttestationStatement\FidoU2FAttestationStatementSupport;
use Webauthn\AttestationStatement\AndroidKeyAttestationStatementSupport;
use Webauthn\AttestationStatement\AndroidSafetyNetAttestationStatementSupport;
use Webauthn\AuthenticationExtensions\ExtensionOutputCheckerHandler;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialLoader;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\TokenBinding\IgnoreTokenBindingHandler;

class WebAuthnManager
{
    protected $attestationStatementSupportManager;
    protected $publicKeyCredentialLoader;
    protected $attestationObjectLoader;
    protected $extensionOutputCheckerHandler;
    protected $coseAlgorithmManager;

    /**
     * WebAuthnManager constructor.
     */
    public function __construct()
    {
        // Set up the COSE Algorithm Manager
        $this->coseAlgorithmManager = new CoseAlgorithmManager();
        $this->coseAlgorithmManager->add(new ES256());
        $this->coseAlgorithmManager->add(new ES384());
        $this->coseAlgorithmManager->add(new RS256());
        $this->coseAlgorithmManager->add(new EdDSA());

        // Set up the Attestation Statement Support Manager
        $this->attestationStatementSupportManager = new AttestationStatementSupportManager();
        $this->attestationStatementSupportManager->add(new NoneAttestationStatementSupport());
        $this->attestationStatementSupportManager->add(new PackedAttestationStatementSupport($this->coseAlgorithmManager));
        $this->attestationStatementSupportManager->add(new TPMAttestationStatementSupport());
        $this->attestationStatementSupportManager->add(new FidoU2FAttestationStatementSupport());
        $this->attestationStatementSupportManager->add(new AndroidKeyAttestationStatementSupport());
        $this->attestationStatementSupportManager->add(new AndroidSafetyNetAttestationStatementSupport(''));

        // Set up the Attestation Object Loader
        $this->attestationObjectLoader = new AttestationObjectLoader($this->attestationStatementSupportManager);

        // Set up Extension Output Checker Handler
        $this->extensionOutputCheckerHandler = new ExtensionOutputCheckerHandler();

        // Set up Public Key Credential Loader
        $this->publicKeyCredentialLoader = new PublicKeyCredentialLoader($this->attestationObjectLoader);
    }

    /**
     * Get the Relying Party Entity
     *
     * @return PublicKeyCredentialRpEntity
     */
    public function getRelyingParty(): PublicKeyCredentialRpEntity
    {
        return new PublicKeyCredentialRpEntity(
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
        
        return new PublicKeyCredentialUserEntity(
            $user->email,
            $userHandle,
            $user->name
        );
    }

    /**
     * Get registered credential sources for a user
     *
     * @param Authenticatable $user
     * @return array
     */
    public function getCredentialSourcesForUser(Authenticatable $user): array
    {
        $credentials = $user->webauthnCredentials;
        
        $sources = [];
        foreach ($credentials as $credential) {
            $sources[] = new PublicKeyCredentialSource(
                $credential->credential_id,
                'public-key',
                [],
                $credential->attestation_type,
                $this->getRelyingParty(),
                $this->getUserEntity($user),
                $credential->public_key,
                $credential->counter ?? 0,
                $credential->attestation_format ?? null
            );
        }
        
        return $sources;
    }

    /**
     * Generate registration options for creating a new credential
     *
     * @param Authenticatable $user
     * @param string $attestation
     * @return array
     */
    public function generateRegistrationOptions(Authenticatable $user, string $attestation = null): array
    {
        // Get existing credentials
        $excludeCredentials = [];
        $credentials = $user->webauthnCredentials;
        
        foreach ($credentials as $credential) {
            $excludeCredentials[] = new PublicKeyCredentialDescriptor(
                'public-key',
                base64_decode($credential->credential_id)
            );
        }
        
        // Create options
        $options = PublicKeyCredentialCreationOptions::create(
            $this->getRelyingParty(),
            $this->getUserEntity($user),
            random_bytes(32), // challenge
            [
                // Define which algorithms are supported
                ['type' => 'public-key', 'alg' => -7],  // ES256
                ['type' => 'public-key', 'alg' => -257], // RS256
                ['type' => 'public-key', 'alg' => -8],   // EdDSA
            ]
        );
        
        // Set attestation conveyance
        $options->setAttestation($attestation ?? Config::get('webauthn.attestation_conveyance', 'none'));
        
        // Set authenticator selection criteria
        $options->setAuthenticatorSelection([
            'userVerification' => Config::get('webauthn.user_verification', 'preferred'),
            'residentKey' => 'preferred',
            'requireResidentKey' => false,
        ]);
        
        // Exclude existing credentials
        if (!empty($excludeCredentials)) {
            $options->setExcludeCredentials($excludeCredentials);
        }
        
        // Return as array for JSON encoding
        return $options->jsonSerialize();
    }

    /**
     * Verify registration response and save the credential
     *
     * @param string $clientResponse
     * @param PublicKeyCredentialCreationOptions $options
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
            // Load creation options from array
            $publicKeyCredentialCreationOptions = PublicKeyCredentialCreationOptions::createFromArray($publicKeyCredentialCreationOptions);
            
            // Parse the client response
            $publicKeyCredential = $this->publicKeyCredentialLoader->load($clientResponse);
            $response = $publicKeyCredential->getResponse();
            
            if (!$response instanceof AuthenticatorAttestationResponse) {
                throw new \Exception('Invalid response type');
            }
            
            // Set up the validator
            $validator = new AuthenticatorAttestationResponseValidator(
                $this->attestationStatementSupportManager,
                null,
                $this->extensionOutputCheckerHandler,
                new IgnoreTokenBindingHandler()
            );
            
            // Validate the response
            $publicKeyCredentialSource = $validator->check(
                $response,
                $publicKeyCredentialCreationOptions,
                Config::get('webauthn.relying_party.id')
            );
            
            // Store the credential
            $user->webauthnCredentials()->create([
                'credential_id' => base64_encode($publicKeyCredentialSource->getPublicKeyCredentialId()),
                'public_key' => $publicKeyCredentialSource->getPublicKey(),
                'attestation_type' => $publicKeyCredentialSource->getAttestationType(),
                'attestation_format' => $publicKeyCredentialSource->getAttestationFormat(),
                'authenticator_data' => [
                    'counter' => $publicKeyCredentialSource->getCounter(),
                    'aaguid' => $publicKeyCredentialSource->getAaguid(),
                ],
                'name' => $credentialName ?? 'Security Key (' . date('Y-m-d H:i:s') . ')',
            ]);
            
            // Mark WebAuthn as enabled for the user
            $user->forceFill([
                'webauthn_enabled' => true,
                'webauthn_confirmed_at' => now(),
            ])->save();
            
            return true;
        } catch (\Exception $e) {
            \Log::error('WebAuthn registration failed: ' . $e->getMessage());
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
        
        // Create request options
        $options = PublicKeyCredentialRequestOptions::create(
            $challenge,
            Config::get('webauthn.relying_party.id')
        );
        
        // Set user verification preference
        $options->setUserVerification(Config::get('webauthn.user_verification', 'preferred'));
        
        // If a specific user is provided, only allow their credentials
        if ($user) {
            $allowCredentials = [];
            $credentials = $user->webauthnCredentials;
            
            foreach ($credentials as $credential) {
                $allowCredentials[] = new PublicKeyCredentialDescriptor(
                    'public-key',
                    base64_decode($credential->credential_id)
                );
            }
            
            if (!empty($allowCredentials)) {
                $options->setAllowCredentials($allowCredentials);
            }
        }
        
        // Return as array for JSON encoding
        return $options->jsonSerialize();
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
            // Load request options from array
            $publicKeyCredentialRequestOptions = PublicKeyCredentialRequestOptions::createFromArray($publicKeyCredentialRequestOptions);
            
            // Parse the client response
            $publicKeyCredential = $this->publicKeyCredentialLoader->load($clientResponse);
            $response = $publicKeyCredential->getResponse();
            
            if (!$response instanceof AuthenticatorAssertionResponse) {
                throw new \Exception('Invalid response type');
            }
            
            // Get credential ID
            $credentialId = base64_encode($publicKeyCredential->getRawId());
            
            // Find the credential in the database
            $credentialModel = \Scriptoshi\LivewireWebauthn\Models\WebAuthnCredential::where('credential_id', $credentialId)->first();
            
            if (!$credentialModel) {
                throw new \Exception('Unknown credential');
            }
            
            // If user is specified, validate it's the correct user
            if ($user && $credentialModel->user_id !== $user->getAuthIdentifier()) {
                throw new \Exception('Credential does not belong to the specified user');
            }
            
            // Get the actual user
            $credentialUser = $credentialModel->user;
            
            // Create the validator
            $validator = new AuthenticatorAssertionResponseValidator(
                null,
                null,
                $this->extensionOutputCheckerHandler,
                new IgnoreTokenBindingHandler()
            );
            
            // Get credential sources for the user
            $credentialSources = $this->getCredentialSourcesForUser($credentialUser);
            
            // Validate the response
            $publicKeyCredentialSource = $validator->check(
                $credentialId,
                $response,
                $publicKeyCredentialRequestOptions,
                Config::get('webauthn.relying_party.id'),
                $credentialSources
            );
            
            // Update counter
            $credentialModel->update([
                'authenticator_data->counter' => $publicKeyCredentialSource->getCounter(),
                'last_used_at' => now(),
            ]);
            
            return $credentialUser;
        } catch (\Exception $e) {
            \Log::error('WebAuthn authentication failed: ' . $e->getMessage());
            return false;
        }
    }
}