<?php

namespace Scriptoshi\LivewireWebauthn\Traits;

use Illuminate\Support\Facades\Auth;
use Illuminate\Validation\ValidationException;
use Scriptoshi\LivewireWebauthn\Facades\WebAuthn;

trait ConfirmsWebAuthn
{
    /**
     * Indicates if the WebAuthn authentication is being confirmed.
     *
     * @var bool
     */
    public $confirmingWebAuthn = false;

    /**
     * The ID of the operation being confirmed.
     *
     * @var string|null
     */
    public $webAuthnConfirmableId = null;

    /**
     * The WebAuthn authentication options.
     *
     * @var array|null
     */
    public $webAuthnOptions = null;

    /**
     * Start confirming the WebAuthn authentication.
     *
     * @param  string  $confirmableId
     * @return void
     */
    public function startConfirmingWebAuthn(string $confirmableId)
    {
        $this->resetErrorBag();

        if ($this->webAuthnIsConfirmed()) {
            return $this->dispatch(
                'webauthn-confirmed',
                id: $confirmableId,
            );
        }

        $this->confirmingWebAuthn = true;
        $this->webAuthnConfirmableId = $confirmableId;
        
        // Generate authentication options for the current user
        $user = Auth::user();
        $this->webAuthnOptions = WebAuthn::generateAuthenticationOptions($user);
        
        $this->dispatch('confirming-webauthn', options: $this->webAuthnOptions);
    }

    /**
     * Stop confirming the WebAuthn authentication.
     *
     * @return void
     */
    public function stopConfirmingWebAuthn()
    {
        $this->confirmingWebAuthn = false;
        $this->webAuthnConfirmableId = null;
        $this->webAuthnOptions = null;
    }

    /**
     * Confirm the WebAuthn authentication.
     *
     * @param string $response
     * @return void
     */
    public function confirmWebAuthn($response)
    {
        $user = Auth::user();
        
        if (!$user->webauthn_enabled) {
            throw ValidationException::withMessages([
                'webauthn' => [__('WebAuthn is not enabled for this account.')],
            ]);
        }
        
        $result = WebAuthn::verifyAuthenticationResponse(
            $response,
            $this->webAuthnOptions,
            $user
        );
        
        if (!$result) {
            throw ValidationException::withMessages([
                'webauthn' => [__('WebAuthn authentication failed. Please try again.')],
            ]);
        }

        session(['auth.webauthn_confirmed_at' => time()]);

        $this->dispatch(
            'webauthn-confirmed',
            id: $this->webAuthnConfirmableId,
        );

        $this->stopConfirmingWebAuthn();
    }

    /**
     * Ensure that the user has recently confirmed their WebAuthn authentication.
     *
     * @param  int|null  $maximumSecondsSinceConfirmation
     * @return void
     */
    protected function ensureWebAuthnIsConfirmed($maximumSecondsSinceConfirmation = null)
    {
        $maximumSecondsSinceConfirmation = $maximumSecondsSinceConfirmation ?: config('webauthn.timeout', 900);

        $this->webAuthnIsConfirmed($maximumSecondsSinceConfirmation) ? null : abort(403);
    }

    /**
     * Determine if the user's WebAuthn authentication has been recently confirmed.
     *
     * @param  int|null  $maximumSecondsSinceConfirmation
     * @return bool
     */
    protected function webAuthnIsConfirmed($maximumSecondsSinceConfirmation = null)
    {
        $maximumSecondsSinceConfirmation = $maximumSecondsSinceConfirmation ?: config('webauthn.timeout', 900);

        return (time() - session('auth.webauthn_confirmed_at', 0)) < $maximumSecondsSinceConfirmation;
    }
}
