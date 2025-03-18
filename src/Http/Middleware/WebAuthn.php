<?php

namespace Scriptoshi\LivewireWebauthn\Http\Middleware;

use Closure;
use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Validation\ValidationException;
use Scriptoshi\LivewireWebauthn\Traits\WebAuthnAuthenticatable;
use Symfony\Component\HttpFoundation\Response;

class WebAuthn
{
    /**
     * The guard implementation.
     *
     * @var \Illuminate\Contracts\Auth\StatefulGuard
     */
    protected $guard;

    /**
     * Create a new middleware instance.
     *
     * @param  \Illuminate\Contracts\Auth\StatefulGuard  $guard
     * @return void
     */
    public function __construct(StatefulGuard $guard = null)
    {
        $this->guard = $guard ?: Auth::guard();
    }

    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure(\Illuminate\Http\Request): (\Symfony\Component\HttpFoundation\Response)  $next
     * @return \Symfony\Component\HttpFoundation\Response
     */
    public function handle(Request $request, Closure $next): Response
    {
        // Validate credentials and get user
        $user = $this->validateCredentials($request);

        if (!$user) {
            return $next($request);
        }

        // Check if WebAuthn is enabled for this user
        if (
            optional($user)->webauthn_enabled &&
            in_array(WebAuthnAuthenticatable::class, class_uses_recursive($user))
        ) {
            return $this->handleWebAuthnChallenge($request, $user);
        }

        return $next($request);
    }

    /**
     * Validate the user credentials.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return mixed
     */
    protected function validateCredentials(Request $request)
    {
        $model = $this->guard->getProvider()->getModel();
        return tap($model::where('email', $request->email)->first(), function ($user) use ($request) {
            if (!$user || !$this->guard->getProvider()->validateCredentials($user, ['password' => $request->password])) {
                $this->throwFailedAuthenticationException($request);
            }
        });
    }

    /**
     * Throw a validation exception for failed authentication.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return void
     *
     * @throws \Illuminate\Validation\ValidationException
     */
    protected function throwFailedAuthenticationException(Request $request)
    {
        throw ValidationException::withMessages([
            'email' => [trans('auth.failed')],
        ]);
    }

    /**
     * Handle the WebAuthn challenge.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  mixed  $user
     * @return \Symfony\Component\HttpFoundation\Response
     */
    protected function handleWebAuthnChallenge(Request $request, $user)
    {
        $request->session()->put([
            'login.id' => $user->getKey(),
            'login.remember' => $request->boolean('remember'),
        ]);

        if ($request->wantsJson()) {
            return response()->json(['webauthn' => true]);
        }

        return redirect()->route('webauthn.challenge');
    }
}
