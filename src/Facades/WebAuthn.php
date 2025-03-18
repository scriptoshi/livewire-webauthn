<?php

namespace Scriptoshi\LivewireWebauthn\Facades;

use Illuminate\Support\Facades\Facade;

/**
 * @method static \Webauthn\PublicKeyCredentialRpEntity getRelyingParty()
 * @method static \Webauthn\PublicKeyCredentialUserEntity getUserEntity(\Illuminate\Contracts\Auth\Authenticatable $user)
 * @method static array getCredentialSourcesForUser(\Illuminate\Contracts\Auth\Authenticatable $user)
 * @method static array generateRegistrationOptions(\Illuminate\Contracts\Auth\Authenticatable $user, string $attestation = null)
 * @method static bool verifyRegistrationResponse(string $clientResponse, array $publicKeyCredentialCreationOptions, \Illuminate\Contracts\Auth\Authenticatable $user, string $credentialName = null)
 * @method static array generateAuthenticationOptions(\Illuminate\Contracts\Auth\Authenticatable $user = null)
 * @method static \Illuminate\Contracts\Auth\Authenticatable|bool verifyAuthenticationResponse(string $clientResponse, array $publicKeyCredentialRequestOptions, \Illuminate\Contracts\Auth\Authenticatable $user = null)
 * 
 * @see \Scriptoshi\LivewireWebauthn\WebAuthnManager
 */
class WebAuthn extends Facade
{
    /**
     * Get the registered name of the component.
     *
     * @return string
     */
    protected static function getFacadeAccessor()
    {
        return 'webauthn';
    }
}