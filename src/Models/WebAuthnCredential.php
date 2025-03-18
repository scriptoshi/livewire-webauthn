<?php

namespace Scriptoshi\LivewireWebauthn\Models;

use Illuminate\Database\Eloquent\Model;

class WebAuthnCredential extends Model
{
    /**
     * The attributes that are mass assignable.
     *
     * @var array
     */
    protected $fillable = [
        'credential_id',
        'public_key',
        'attestation_type',
        'attestation_format',
        'authenticator_data',
        'name',
        'last_used_at',
    ];

    /**
     * The attributes that should be cast.
     *
     * @var array
     */
    protected $casts = [
        'authenticator_data' => 'array',
        'last_used_at' => 'datetime',
    ];

    /**
     * Get the user that owns the credential.
     *
     * @return \Illuminate\Database\Eloquent\Relations\BelongsTo
     */
    public function user()
    {
        return $this->belongsTo(config('auth.providers.users.model'));
    }
}
