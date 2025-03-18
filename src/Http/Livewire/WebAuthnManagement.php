<?php

namespace Scriptoshi\LivewireWebauthn\Http\Livewire;

use Illuminate\Support\Facades\Auth;
use Livewire\Component;
use Scriptoshi\LivewireWebauthn\Facades\WebAuthn;
use Scriptoshi\LivewireWebauthn\Traits\ConfirmsWebAuthn;

class WebAuthnManagement extends Component
{
    public $enabled = false;
    public $credentials = [];
    public $newCredentialName = '';
    public $registrationOptions = null;
    public $isRegistering = false;
    public $message = '';
    public $messageType = '';

    public function mount()
    {
        $user = Auth::user();
        $this->enabled = $user->webauthn_enabled;
        $this->refreshCredentials();
    }

    public function refreshCredentials()
    {
        $user = Auth::user();
        $this->credentials = $user->webauthnCredentials()->latest()->get();
    }

    public function startRegistration()
    {
        $this->resetErrorBag();
        $this->message = '';
        $this->messageType = '';

        $user = Auth::user();
        $this->registrationOptions = WebAuthn::generateRegistrationOptions($user);
        $this->isRegistering = true;

        $this->dispatch('webauthn-registration-started', options: $this->registrationOptions);
    }

    public function completeRegistration($response, $credentialName = null)
    {
        $this->resetErrorBag();
        $this->message = '';
        $this->messageType = '';

        if (empty($credentialName)) {
            $credentialName = $this->newCredentialName ?: 'Security Key';
        }

        $user = Auth::user();
        
        if (WebAuthn::verifyRegistrationResponse($response, $this->registrationOptions, $user, $credentialName)) {
            $this->registrationOptions = null;
            $this->isRegistering = false;
            $this->newCredentialName = '';
            $this->enabled = true;
            $this->refreshCredentials();
            
            $this->message = 'Security key registered successfully!';
            $this->messageType = 'success';
            
            $this->dispatch('webauthn-credential-registered');
        } else {
            $this->addError('registration', 'Failed to register security key. Please try again.');
            $this->messageType = 'error';
        }
    }

    public function cancelRegistration()
    {
        $this->registrationOptions = null;
        $this->isRegistering = false;
        $this->newCredentialName = '';
        $this->resetErrorBag();
    }

    public function removeCredential($credentialId)
    {
        $user = Auth::user();
        $credential = $user->webauthnCredentials()->where('id', $credentialId)->first();
        
        if ($credential) {
            $credential->delete();
            
            // Check if this was the last credential, if so, disable WebAuthn
            if ($user->webauthnCredentials()->count() === 0) {
                $user->forceFill(['webauthn_enabled' => false])->save();
                $this->enabled = false;
            }
            
            $this->refreshCredentials();
            
            $this->message = 'Security key removed successfully!';
            $this->messageType = 'success';
            
            $this->dispatch('webauthn-credential-removed');
        }
    }

    public function render()
    {
        return view('webauthn::livewire.webauthn-management');
    }
}
