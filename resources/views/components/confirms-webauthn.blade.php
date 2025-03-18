@props(['title' => __('Verify WebAuthn Authentication'), 'content' => __('For additional security, please authenticate with your security key or biometrics to continue.'), 'button' => __('Verify')])

@php
    $confirmableId = md5($attributes->wire('then'));
@endphp

<span
    {{ $attributes->wire('then') }}
    x-data
    x-ref="span"
    x-on:click="$wire.startConfirmingWebAuthn('{{ $confirmableId }}')"
    x-on:webauthn-confirmed.window="setTimeout(() => $event.detail.id === '{{ $confirmableId }}' && $refs.span.dispatchEvent(new CustomEvent('then', { bubbles: false })), 250);"
>
    {{ $slot }}
</span>

@once
<flux:modal wire:model.live="confirmingWebAuthn" class="md:w-96">
    <div class="space-y-6">
        <div>
            <flux:heading size="lg">{{ $title }}</flux:heading>
            <flux:subheading>{{ $content }}</flux:subheading>
        </div>

        <div 
            x-data="{
                webAuthnAuth() {
                    if (!$wire.webAuthnOptions) return;
                    
                    // Create new AbortController
                    if (window.abortController) {
                        window.abortController.abort();
                    }
                    window.abortController = new AbortController();
                    
                    // Prepare options
                    const publicKey = {
                        challenge: this.base64UrlDecode($wire.webAuthnOptions.challenge),
                        rpId: $wire.webAuthnOptions.rpId,
                        userVerification: $wire.webAuthnOptions.userVerification || 'preferred',
                        timeout: $wire.webAuthnOptions.timeout || 60000,
                    };
                    
                    if ($wire.webAuthnOptions.allowCredentials && $wire.webAuthnOptions.allowCredentials.length > 0) {
                        publicKey.allowCredentials = $wire.webAuthnOptions.allowCredentials.map(cred => ({
                            id: this.base64UrlDecode(cred.id),
                            type: cred.type,
                            transports: cred.transports || ['usb', 'ble', 'nfc', 'internal']
                        }));
                    }
                    
                    // Start authentication
                    navigator.credentials.get({
                        publicKey,
                        signal: window.abortController.signal
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
                        
                        $wire.confirmWebAuthn(JSON.stringify(response));
                    })
                    .catch(error => {
                        console.error('WebAuthn Authentication Error:', error);
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
            x-init="$watch('$wire.webAuthnOptions', value => { if (value) setTimeout(() => webAuthnAuth(), 250); })"
        >
            <div class="text-center py-8">
                <div class="inline-flex items-center justify-center w-16 h-16 rounded-full bg-blue-100 text-blue-500 mb-4">
                    <svg xmlns="http://www.w3.org/2000/svg" class="h-8 w-8" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 11c0 3.517-1.009 6.799-2.753 9.571m-3.44-2.04l.054-.09A13.916 13.916 0 008 11a4 4 0 118 0c0 1.017-.07 2.019-.203 3m-2.118 6.844A21.88 21.88 0 0015.171 17m3.839 1.132c.645-2.266.99-4.659.99-7.132A8 8 0 008 4.07M3 15.364c.64-1.319 1-2.8 1-4.364 0-1.457.39-2.823 1.07-4" />
                    </svg>
                </div>
                <p class="text-gray-600 dark:text-gray-400">
                    {{ __('Waiting for security key or biometric verification...') }}
                </p>
            </div>

            <flux:error name="webauthn" class="mt-2" />
        </div>

        <div class="flex gap-2">
            <flux:spacer />

            <flux:button variant="ghost" wire:click="stopConfirmingWebAuthn" x-on:click="if (window.abortController) window.abortController.abort();" wire:loading.attr="disabled">
                {{ __('Cancel') }}
            </flux:button>
        </div>
    </div>
</flux:modal>
@endonce
