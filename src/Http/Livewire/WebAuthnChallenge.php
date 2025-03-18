<?php

namespace Scriptoshi\LivewireWebauthn\Http\Livewire;

use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Support\Facades\Auth;
use Livewire\Component;
use Scriptoshi\LivewireWebauthn\Facades\WebAuthn;

class WebAuthnChallenge extends Component
{
    public $authOptions = null;
    public $message = '';
    public $usePasskey = false;

    /**
     * Mount the component.
     *
     * @return void
     */
    public function mount()
    {
        if (!session()->has('login.id')) {
            return redirect()->route('login');
        }

        $userModel = config('auth.providers.users.model');
        $user = $userModel::find(session('login.id'));
        
        if (!$user) {
            return redirect()->route('login');
        }

        $this->authOptions = WebAuthn::generateAuthenticationOptions($user);
        $this->dispatch('webauthn-authentication-started', options: $this->authOptions);
    }

    /**
     * Toggle between passkey and security key options.
     *
     * @return void
     */
    public function togglePasskey()
    {
        $this->usePasskey = !$this->usePasskey;
    }

    /**
     * Handle the authentication response.
     *
     * @param string $response
     * @param \Illuminate\Contracts\Auth\StatefulGuard $guard
     * @return \Illuminate\Http\RedirectResponse|void
     */
    public function authenticate($response, StatefulGuard $guard = null)
    {
        $guard = $guard ?: Auth::guard();
        $this->resetErrorBag();
        $this->message = '';

        $userModel = config('auth.providers.users.model');
        $user = $userModel::find(session('login.id'));
        
        if (!$user) {
            return redirect()->route('login');
        }

        $result = WebAuthn::verifyAuthenticationResponse(
            $response, 
            $this->authOptions,
            $user
        );

        if ($result) {
            $guard->login($user, session('login.remember', false));

            session()->forget('login.id');
            session()->forget('login.remember');

            return redirect()->intended(route('dashboard'));
        } else {
            $this->message = __('Authentication failed. Please try again.');
        }
    }

    /**
     * Cancel authentication and return to login.
     *
     * @return \Illuminate\Http\RedirectResponse
     */
    public function cancel()
    {
        session()->forget(['login.id', 'login.remember']);
        return redirect()->route('login');
    }

    /**
     * Render the component.
     *
     * @return \Illuminate\View\View
     */
    public function render()
    {
        return view('webauthn::livewire.webauthn-challenge');
    }
}
