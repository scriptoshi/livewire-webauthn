<section class="mt-5 space-y-6 w-full">
    @if ($message)
        <div class="p-4 mb-4 rounded {{ $messageType === 'success' ? 'bg-green-50 text-green-800 dark:bg-green-900 dark:text-green-100' : 'bg-red-50 text-red-800 dark:bg-red-900 dark:text-red-100' }}">
            {{ $message }}
        </div>
    @endif

    @if ($isRegistering)
        <div class="bg-white dark:bg-gray-850">
            <flux:heading size="lg">
                {{ __('Register a new security key') }}
            </flux:heading>

            <div class="mt-4">
                <flux:input 
                    wire:model="newCredentialName" 
                    placeholder="{{ __('Security Key Name (e.g. Yubikey, Phone)') }}" 
                    class="w-full mb-4"
                />
            </div>

            <div 
                x-data="{
                    register() {
                        if (!@js($registrationOptions)) return;
                        
                        // Prepare registration options
                        const publicKey = {
                            challenge: this.base64UrlDecode(@js($registrationOptions['challenge'])),
                            rp: {
                                name: @js($registrationOptions['rp']['name']),
                                id: @js($registrationOptions['rp']['id'])
                            },
                            user: {
                                id: this.base64UrlDecode(@js($registrationOptions['user']['id'])),
                                name: @js($registrationOptions['user']['name']),
                                displayName: @js($registrationOptions['user']['displayName'])
                            },
                            pubKeyCredParams: @js($registrationOptions['pubKeyCredParams']),
                            timeout: @js($registrationOptions['timeout']??6000) || 60000,
                            attestation: @js($registrationOptions['attestation']) || 'none',
                            authenticatorSelection: @js($registrationOptions['authenticatorSelection']) || {}
                        };
                        
                        if (@js($registrationOptions['excludeCredentials']) && @js($registrationOptions['excludeCredentials']).length > 0) {
                            publicKey.excludeCredentials = @js($registrationOptions['excludeCredentials']).map(cred => ({
                                id: this.base64UrlDecode(cred.id),
                                type: cred.type,
                                transports: cred.transports || ['usb', 'ble', 'nfc', 'internal']
                            }));
                        }
                        
                        // Start registration
                        navigator.credentials.create({
                            publicKey
                        })
                        .then(credential => {
                            const attestationResponse = credential.response;
                            
                            const response = {
                                id: credential.id,
                                rawId: this.base64UrlEncode(credential.rawId),
                                type: credential.type,
                                response: {
                                    clientDataJSON: this.base64UrlEncode(attestationResponse.clientDataJSON),
                                    attestationObject: this.base64UrlEncode(attestationResponse.attestationObject),
                                    transports: attestationResponse.getTransports ? attestationResponse.getTransports() : []
                                }
                            };
                            
                            $wire.completeRegistration(JSON.stringify(response), $wire.newCredentialName);
                        })
                        .catch(error => {
                            console.error('WebAuthn Registration Error:', error);
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
                x-init="register()"
                class="py-8"
            >
                <div class="text-center">
                    <div class="inline-flex items-center justify-center w-16 h-16 rounded-full bg-blue-100 text-blue-500 mb-4">
                        <svg xmlns="http://www.w3.org/2000/svg" class="h-8 w-8" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 11c0 3.517-1.009 6.799-2.753 9.571m-3.44-2.04l.054-.09A13.916 13.916 0 008 11a4 4 0 118 0c0 1.017-.07 2.019-.203 3m-2.118 6.844A21.88 21.88 0 0015.171 17m3.839 1.132c.645-2.266.99-4.659.99-7.132A8 8 0 008 4.07M3 15.364c.64-1.319 1-2.8 1-4.364 0-1.457.39-2.823 1.07-4" />
                        </svg>
                    </div>
                    <p class="text-gray-600 dark:text-gray-400">
                        {{ __('Please follow your browser\'s instructions to register your security key...') }}
                    </p>
                </div>

                @error('registration')
                    <div class="mt-2 text-sm text-red-600 dark:text-red-400">
                        {{ $message }}
                    </div>
                @enderror
            </div>

            <div class="mt-4 flex justify-end">
                <flux:button variant="ghost" wire:click="cancelRegistration" wire:loading.attr="disabled">
                    {{ __('Cancel') }}
                </flux:button>
            </div>
        </div>
    @elseif (!$enabled || count($credentials) === 0)
        <div class="bg-white dark:bg-gray-850">
            <flux:heading size="lg">
                {{ __('Security Key or Biometric authentication is not Enabled') }}
            </flux:heading>

            <div class="mt-3 max-w-xl text-sm text-gray-600 dark:text-gray-400">
                <p>
                    {{ __('Use hardware security keys, biometrics auth (like fingerprint or facial recognition), or your mobile device for secure authentication without passwords.') }}
                </p>
            </div>

            <div class="mt-5">
                <flux:button type="button" wire:click="startRegistration" wire:loading.attr="disabled">
                    {{ __('Add Security Key') }}
                </flux:button>
            </div>
        </div>
    @else
        <div class="bg-white dark:bg-gray-850">
            <flux:heading size="lg">
                {{ __('Security Keys') }}
            </flux:heading>

            <div class="mt-3 max-w-xl text-sm text-gray-600 dark:text-gray-400">
                <p>
                    {{ __('You can add multiple security keys for authentication. Using security keys provides strong protection against phishing and account takeovers.') }}
                </p>
            </div>

            <div class="mt-6">
                <div class="bg-gray-50 dark:bg-gray-700 rounded-lg overflow-hidden">
                    <div class="divide-y divide-gray-200 dark:divide-gray-600">
                        @forelse ($credentials as $credential)
                            <div class="p-4 flex items-center justify-between">
                                <div class="flex items-center">
                                    <div class="mr-3 text-blue-500 dark:text-blue-400">
                                        <svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" />
                                        </svg>
                                    </div>
                                    <div>
                                        <div class="font-medium text-gray-900 dark:text-gray-100">
                                            {{ $credential->name }}
                                        </div>
                                        <div class="text-xs text-gray-500 dark:text-gray-400">
                                            {{ __('Last used') }}: {{ $credential->last_used_at ? $credential->last_used_at->diffForHumans() : __('Never') }}
                                        </div>
                                    </div>
                                </div>

                                <div class="flex items-center">
                                    <button
                                        type="button"
                                        class="inline-flex items-center text-red-600 dark:text-red-400 hover:text-red-800 dark:hover:text-red-300"
                                        wire:click="removeCredential({{ $credential->id }})"
                                        wire:loading.attr="disabled"
                                    >
                                        <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                                        </svg>
                                        {{ __('Remove') }}
                                    </button>
                                </div>
                            </div>
                        @empty
                            <div class="p-4 text-center text-gray-500 dark:text-gray-400">
                                {{ __('No security keys registered yet.') }}
                            </div>
                        @endforelse
                    </div>
                </div>
            </div>

            <div class="mt-6">
                <flux:button type="button" wire:click="startRegistration" wire:loading.attr="disabled">
                    {{ __('Add Another Security Key') }}
                </flux:button>
            </div>
        </div>
    @endif
</section>