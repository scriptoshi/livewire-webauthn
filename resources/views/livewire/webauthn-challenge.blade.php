<div>
    <div class="mb-4 text-sm text-gray-600 dark:text-gray-400">
        {{ __('Please confirm access to your account by using your security key or biometric authentication.') }}
    </div>

    @if (session('status'))
        <div class="mb-4 font-medium text-sm text-green-600 dark:text-green-400">
            {{ session('status') }}
        </div>
    @endif

    @if ($message)
        <div class="mb-4 font-medium text-sm text-red-600 dark:text-red-400">
            {{ $message }}
        </div>
    @endif

    <div class="mt-8"
        x-data="{
            webAuthnAuth() {
                if (!@js($authOptions)) return;
                
                // Prepare options
                const publicKey = {
                    challenge: this.base64UrlDecode(@js($authOptions['challenge'])),
                    rpId: @js($authOptions['rpId']),
                    userVerification: @js($authOptions['userVerification']) || 'preferred',
                    timeout: @js($authOptions['timeout']??60000) || 60000,
                };
                
                if (@js($authOptions['allowCredentials']) && @js($authOptions['allowCredentials']).length > 0) {
                    publicKey.allowCredentials = @js($authOptions['allowCredentials']).map(cred => ({
                        id: this.base64UrlDecode(cred.id),
                        type: cred.type,
                        transports: cred.transports || ['usb', 'ble', 'nfc', 'internal']
                    }));
                }
                
                // Start authentication
                navigator.credentials.get({
                    publicKey,
                })
                .then(credential => {
                    const response = {
                        id: credential.id,
                        rawId: this.base64UrlEncode(credential.rawId),
                        type: credential.type,
                        response: {
                            clientDataJSON: this.base64UrlEncode(credential.response.clientDataJSON),
                            authenticatorData: this.base64UrlEncode(credential.response.authenticatorData),
                            signature: this.base64UrlEncode(credential.response.signature),
                            userHandle: credential.response.userHandle ? this.base64UrlEncode(credential.response.userHandle) : null
                        }
                    };
                    
                    $wire.authenticate(JSON.stringify(response));
                })
                .catch(error => {
                    console.error('Biometric/Security key Authentication Error:', error);
                });
            },
            
            base64UrlDecode(base64Url) {
                const padding = '='.repeat((4 - (base64Url.length % 4)) % 4);
                const base64 = (base64Url + padding)
                    .replace(/-/g, '+')
                    .replace(/_/g, '/');
                
                return Uint8Array.from(atob(base64), c => c.charCodeAt(0));
            },
            
            base64UrlEncode(buffer) {
                return btoa(String.fromCharCode(...new Uint8Array(buffer)))
                    .replace(/\+/g, '-')
                    .replace(/\//g, '_')
                    .replace(/=/g, '');
            }
        }"
        x-init="$nextTick(() => { if (@js($usePasskey)) { webAuthnAuth(); }});"
    >
        <div class="flex items-center justify-center p-6 bg-gray-50 dark:bg-gray-800 rounded-lg">
            <div class="text-center">
                <div class="inline-flex items-center justify-center w-16 h-16 rounded-full bg-blue-100 dark:bg-blue-900 text-blue-500 dark:text-blue-300 mb-4">
                    <svg xmlns="http://www.w3.org/2000/svg" class="h-8 w-8" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 11c0 3.517-1.009 6.799-2.753 9.571m-3.44-2.04l.054-.09A13.916 13.916 0 008 11a4 4 0 118 0c0 1.017-.07 2.019-.203 3m-2.118 6.844A21.88 21.88 0 0015.171 17m3.839 1.132c.645-2.266.99-4.659.99-7.132A8 8 0 008 4.07M3 15.364c.64-1.319 1-2.8 1-4.364 0-1.457.39-2.823 1.07-4" />
                    </svg>
                </div>
                
                @if($usePasskey)
                    <h3 class="text-lg font-medium text-gray-900 dark:text-gray-100 mb-2">
                        {{ __('Authenticating...') }}
                    </h3>
                    <p class="text-sm text-gray-600 dark:text-gray-400 mb-4">
                        {{ __('Please follow your browser\'s instructions to complete authentication.') }}
                    </p>
                @else
                    <h3 class="text-lg font-medium text-gray-900 dark:text-gray-100 mb-2">
                        {{ __('Use your security key') }}
                    </h3>
                    <p class="text-sm text-gray-600 dark:text-gray-400 mb-4">
                        {{ __('Connect and tap your security key to authenticate.') }}
                    </p>
                    
                    <flux:button x-on:click="webAuthnAuth()" class="mb-2">
                        {{ __('Authenticate with Security Key') }}
                    </flux:button>
                @endif
                
                <div class="mt-4">
                    <button type="button" wire:click="togglePasskey" class="text-sm text-blue-600 dark:text-blue-400 hover:underline">
                        {{ $usePasskey ? __('Use security key instead') : __('Use passkey instead') }}
                    </button>
                </div>
            </div>
        </div>

        <div class="flex items-center justify-end mt-4">
            <button type="button"
                class="text-sm text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-gray-100 underline cursor-pointer"
                wire:click="cancel">
                {{ __('Cancel and return to login') }}
            </button>
        </div>
    </div>
</div>