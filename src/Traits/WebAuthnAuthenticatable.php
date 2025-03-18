<?php

namespace Scriptoshi\LivewireWebauthn\Traits;

use Scriptoshi\LivewireWebauthn\Models\WebAuthnCredential;

trait WebAuthnAuthenticatable
{
    /**
     * Get WebAuthn credentials for this user.
     *
     * @return \Illuminate\Database\Eloquent\Relations\HasMany
     */
    public function webauthnCredentials()
    {
        return $this->hasMany(WebAuthnCredential::class);
    }

    /**
     * Determine if WebAuthn has been enabled.
     *
     * @return bool
     */
    public function hasEnabledWebAuthn()
    {
        return $this->webauthn_enabled && $this->webauthnCredentials()->count() > 0;
    }
}
