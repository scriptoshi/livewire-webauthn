<?php

namespace Scriptoshi\LivewireWebauthn\Repository;

use Illuminate\Support\Facades\Log;
use Ramsey\Uuid\Uuid as RamseyUuid;
use Symfony\Component\Uid\Uuid;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\TrustPath\EmptyTrustPath;
use Scriptoshi\LivewireWebauthn\Models\WebAuthnCredential;

class WebAuthnCredentialRepository
{
    /**
     * Find a credential by ID
     *
     * @param string $publicKeyCredentialId
     * @return PublicKeyCredentialSource|null
     */
    public function findOneByCredentialId(string $publicKeyCredentialId): ?PublicKeyCredentialSource
    {
        $encodedId = base64_encode($publicKeyCredentialId);
        $credential = WebAuthnCredential::where('credential_id', $encodedId)->first();

        if (!$credential) {
            return null;
        }

        try {
            // Convert stored AAGUID to Symfony Uuid
            $aaguidValue = $credential->authenticator_data['aaguid'] ?? '00000000-0000-0000-0000-000000000000';
            $aaguid = Uuid::fromString($aaguidValue);

            // Create the PublicKeyCredentialSource object
            return PublicKeyCredentialSource::create(
                $publicKeyCredentialId,                     // publicKeyCredentialId
                'public-key',                              // type
                [],                                        // transports (empty array)
                $credential->attestation_type,             // attestationType
                new EmptyTrustPath(),                      // trustPath
                $aaguid,                                   // aaguid
                $credential->public_key,                   // credentialPublicKey
                $this->getUserHandleByUserId($credential->user_id), // userHandle
                $credential->authenticator_data['counter'] ?? 0, // counter
                null,                                      // otherUI
                null,                                      // backupEligible
                null,                                      // backupStatus
                null                                       // uvInitialized
            );
        } catch (\Exception $e) {
            Log::error('Error converting credential to PublicKeyCredentialSource: ' . $e->getMessage());
            return null;
        }
    }

    /**
     * Find all credentials for a user
     *
     * @param string $userHandle
     * @return array
     */
    public function findAllForUserEntity(string $userHandle): array
    {
        // Get the user ID from the user handle
        $userId = $this->getUserIdByUserHandle($userHandle);

        if (!$userId) {
            return [];
        }

        // Get all credentials for this user
        $credentials = WebAuthnCredential::where('user_id', $userId)->get();
        $sources = [];

        foreach ($credentials as $credential) {
            try {
                // Convert stored AAGUID to Symfony Uuid
                $aaguidValue = $credential->authenticator_data['aaguid'] ?? '00000000-0000-0000-0000-000000000000';
                $aaguid = Uuid::fromString($aaguidValue);

                $sources[] = PublicKeyCredentialSource::create(
                    base64_decode($credential->credential_id), // publicKeyCredentialId
                    'public-key',                             // type
                    [],                                       // transports
                    $credential->attestation_type,            // attestationType
                    new EmptyTrustPath(),                     // trustPath
                    $aaguid,                                  // aaguid
                    $credential->public_key,                  // credentialPublicKey
                    $userHandle,                              // userHandle
                    $credential->authenticator_data['counter'] ?? 0, // counter
                    null,                                     // otherUI
                    null,                                     // backupEligible
                    null,                                     // backupStatus
                    null                                      // uvInitialized
                );
            } catch (\Exception $e) {
                Log::error('Error converting credential to PublicKeyCredentialSource: ' . $e->getMessage());
            }
        }

        return $sources;
    }

    /**
     * Save a credential source
     *
     * @param PublicKeyCredentialSource $publicKeyCredentialSource
     * @param int|null $userId Optional user ID if already known
     * @param string|null $credentialName Optional friendly name for the credential
     */
    public function saveCredentialSource(
        PublicKeyCredentialSource $publicKeyCredentialSource,
        ?int $userId = null,
        ?string $credentialName = null
    ): void {
        // If user ID not provided, try to get it from the user handle
        if ($userId === null) {
            $userId = $this->getUserIdByUserHandle($publicKeyCredentialSource->userHandle);

            if (!$userId) {
                Log::error('Could not find user ID for credential source');
                return;
            }
        }

        $encodedId = base64_encode($publicKeyCredentialSource->publicKeyCredentialId);
        $credential = WebAuthnCredential::where('credential_id', $encodedId)->first();

        // Extract data from the credential source
        $credentialData = [
            'user_id' => $userId,
            'credential_id' => $encodedId,
            'public_key' => $publicKeyCredentialSource->credentialPublicKey,
            'attestation_type' => $publicKeyCredentialSource->attestationType,
            'authenticator_data' => [
                'counter' => $publicKeyCredentialSource->counter,
                'aaguid' => $publicKeyCredentialSource->aaguid->toRfc4122(),
            ],
        ];

        if ($credential) {
            // Update existing credential
            $credential->update($credentialData);
        } else {
            // Create new credential
            $credentialData['name'] = $credentialName ?? 'Security Key (' . date('Y-m-d H:i:s') . ')';
            WebAuthnCredential::create($credentialData);
        }
    }

    /**
     * Update a credential's last used timestamp
     *
     * @param string $credentialId
     * @param int $userId
     * @return void
     */
    public function updateCredentialLastUsed(string $credentialId, int $userId): void
    {
        $encodedId = base64_encode($credentialId);

        WebAuthnCredential::where('credential_id', $encodedId)
            ->where('user_id', $userId)
            ->update(['last_used_at' => now()]);
    }

    /**
     * Get a user entity by a credential source
     *
     * @param PublicKeyCredentialSource $credentialSource
     * @return PublicKeyCredentialUserEntity
     */
    public function getUserEntityByCredentialSource(PublicKeyCredentialSource $credentialSource): PublicKeyCredentialUserEntity
    {
        $userId = $this->getUserIdByUserHandle($credentialSource->userHandle);

        if (!$userId) {
            throw new \RuntimeException('User not found for credential');
        }

        $userModel = config('auth.providers.users.model');
        $user = $userModel::find($userId);

        if (!$user) {
            throw new \RuntimeException('User not found for credential');
        }

        return PublicKeyCredentialUserEntity::create(
            $user->email,
            $credentialSource->userHandle,
            $user->name
        );
    }

    /**
     * Get a user ID by a credential source
     *
     * @param PublicKeyCredentialSource $credentialSource
     * @return int|null
     */
    public function getUserIdByCredentialSource(PublicKeyCredentialSource $credentialSource): ?int
    {
        $encodedId = base64_encode($credentialSource->publicKeyCredentialId);
        $credential = WebAuthnCredential::where('credential_id', $encodedId)->first();

        return $credential ? $credential->user_id : null;
    }

    /**
     * Get user handle for a specific user ID
     *
     * @param int $userId
     * @return string
     */
    private function getUserHandleByUserId(int $userId): string
    {
        $userModel = config('auth.providers.users.model');
        $user = $userModel::find($userId);

        if (!$user) {
            throw new \RuntimeException('User not found');
        }

        return RamseyUuid::uuid5(RamseyUuid::NAMESPACE_OID, $user->getAuthIdentifier())->toString();
    }

    /**
     * Get user ID from a user handle
     *
     * @param string $userHandle
     * @return int|null
     */
    private function getUserIdByUserHandle(string $userHandle): ?int
    {
        $userModel = config('auth.providers.users.model');
        $users = $userModel::all();

        foreach ($users as $user) {
            $currentHandle = RamseyUuid::uuid5(RamseyUuid::NAMESPACE_OID, $user->getAuthIdentifier())->toString();
            if ($currentHandle === $userHandle) {
                return $user->getAuthIdentifier();
            }
        }

        return null;
    }
}
