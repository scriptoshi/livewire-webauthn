# Laravel Livewire WebAuthn

A modern WebAuthn (FIDO2) authentication package for Laravel 12 using Livewire and Flux components. Enables passwordless and two-factor authentication using security keys, biometrics, and mobile devices.

## Overview

Laravel Livewire WebAuthn provides an easy way to integrate WebAuthn (Web Authentication) capabilities into your Laravel 12 application. Built with Livewire and Flux components, it offers a modern, interactive user experience with minimal configuration.

### Features

-   🔐 FIDO2 WebAuthn standard compliant
-   🔑 Support for security keys (YubiKey, Titan, etc.)
-   👆 Support for biometrics (TouchID, FaceID, Windows Hello)
-   📱 Support for mobile devices as authenticators
-   ⚡ Livewire-powered interactive components
-   🎨 Beautiful UI with Flux components
-   🌓 Full dark mode support
-   🛠️ Simple integration with existing authentication systems
-   🛡️ On-demand WebAuthn confirmation modals
-   🔄 Compatible with Laravel 12 and Livewire 3

## Requirements

-   PHP 8.2+
-   Laravel 12.x
-   Livewire 3.x
-   Flux components
-   A browser that supports WebAuthn (most modern browsers)

## Installation

### 1. Install the package via Composer

```bash
composer require scriptoshi/livewire-webauthn
```

### 2. (Optional) Publish the assets if you need to customize them

```bash
php artisan vendor:publish --provider="Scriptoshi\LivewireWebauthn\WebAuthnServiceProvider" --tag="config"
php artisan vendor:publish --provider="Scriptoshi\LivewireWebauthn\WebAuthnServiceProvider" --tag="views"
php artisan vendor:publish --provider="Scriptoshi\LivewireWebauthn\WebAuthnServiceProvider" --tag="migrations"
```

### 3. Run the migrations

This will add the required columns to your users table and create the credentials table.

```bash
php artisan migrate
```

### 4. Include the WebAuthnAuthenticatable trait in your User model

```php
use Scriptoshi\LivewireWebauthn\Traits\WebAuthnAuthenticatable;

class User extends Authenticatable
{
    use WebAuthnAuthenticatable;

    // ...
}
```

## Configuration

The package comes with sensible defaults, but you can customize it using the corresponding `.env` variables.
Add the following lines to your .env to customize the configuration:

```bash
# Enable or disable WebAuthn functionality entirely
WEBAUTHN_ENABLED=true

# Relying party name (shown to users during authentication)
WEBAUTHN_RP_NAME="${APP_NAME}"

# Relying party ID (usually your domain name)
WEBAUTHN_RP_ID="${APP_URL}"

# Table name for WebAuthn credentials
WEBAUTHN_CREDENTIALS_TABLE=webauthn_credentials

# Timeout for WebAuthn verification (in seconds, default 15 minutes)
WEBAUTHN_TIMEOUT=900

# Attestation conveyance preference (none, indirect, direct, enterprise)
WEBAUTHN_ATTESTATION_CONVEYANCE=none

# User verification requirement (required, preferred, discouraged)
WEBAUTHN_USER_VERIFICATION=preferred
```

## Basic Usage

### Integrating with Login as Second factor Auth.

Add the middleware to your login logic. If you're using Laravel's built-in authentication:

1. Add this to your `routes/web.php`:

```php
use Scriptoshi\LivewireWebauthn\Http\Middleware\WebAuthn;

// Intercept login attempts and handle WebAuthn if needed
Route::post('/login', [AuthenticatedSessionController::class, 'store'])
    ->middleware(['guest', WebAuthn::class])
    ->name('login');
```

### Adding WebAuthn Management to User Profile

Add the Livewire component to your user profile or settings page:

```blade
<livewire:webauthn-management />
```

With Laravel 12 Starter Kit, you can add a new section for WebAuthn management:

1. Edit `resources/views/components/settings/layout.blade.php` to add the menu item:

```blade
<flux:navlist>
    <flux:navlist.item :href="route('settings.profile')" wire:navigate>{{ __('Profile') }}</flux:navlist.item>
    <flux:navlist.item :href="route('settings.password')" wire:navigate>{{ __('Password') }}</flux:navlist.item>
    <flux:navlist.item :href="route('settings.appearance')" wire:navigate>{{ __('Appearance') }}</flux:navlist.item>
    <!-- Add WebAuthn -->
    <flux:navlist.item :href="route('settings.webauthn')" wire:navigate>{{ __('Security Keys') }}</flux:navlist.item>
</flux:navlist>
```

2. Then Create a WebAuthn view:
   `resources/views/livewire/settings/webauthn.blade.php`

```blade
<?php
use Livewire\Volt\Component;

new class extends Component {

}; ?>

<section class="w-full">
    @include('partials.settings-heading')
    <x-settings.layout :heading="__('Security Keys')" :subheading="__('Manage security keys and biometric devices')">
        <livewire:webauthn-management />
    </x-settings.layout>
</section>
```

3. Add the route to `routes/web.php`:

```php
Volt::route('settings/webauthn', 'settings.webauthn')->name('settings.webauthn');
```

That's it! The component will handle registering, managing, and using WebAuthn credentials.

## Using WebAuthn Confirmation Modals

For enhanced security, you can require WebAuthn confirmation for sensitive operations. This is similar to password confirmation but uses a security key or biometric instead.

1. Include the trait in your Livewire component:

```php
use Scriptoshi\LivewireWebauthn\Traits\ConfirmsWebAuthn;

class AdminSettings extends Component
{
    use ConfirmsWebAuthn;

    /**
     * Enable administration mode for user.
     */
    public function enableAdminMode(): void
    {
        $this->ensureWebAuthnIsConfirmed();

        // Critical operation code here...
    }
}
```

2. Wrap the sensitive action in your component:

```blade
<x-confirms-webauthn wire:then="enableAdminMode">
    <flux:button type="button" wire:loading.attr="disabled">
        {{ __('Enable Admin Mode') }}
    </flux:button>
</x-confirms-webauthn>
```

## Advanced Usage

### Using the Facade Directly

You can use the `WebAuthn` facade directly for advanced use cases:

```php
use Scriptoshi\LivewireWebauthn\Facades\WebAuthn;

// Generate registration options
$options = WebAuthn::generateRegistrationOptions($user);

// Verify a WebAuthn response
$result = WebAuthn::verifyRegistrationResponse($response, $options, $user, 'My Security Key');

// Generate authentication options
$authOptions = WebAuthn::generateAuthenticationOptions($user);

// Verify authentication response
$authenticatedUser = WebAuthn::verifyAuthenticationResponse($response, $authOptions, $user);
```

### Event Handling

The package dispatches Livewire events that you can listen for:

-   `webauthn-registration-started` - When registration begins
-   `webauthn-credential-registered` - When a credential is registered
-   `webauthn-credential-removed` - When a credential is removed
-   `webauthn-authentication-started` - When authentication begins
-   `webauthn-confirmed` - When WebAuthn verification is confirmed

Use these events in your Livewire components to respond to WebAuthn actions.

## Client-Side Implementation

The package includes all necessary JavaScript for interacting with the WebAuthn API. The included functions handle:

1. **Base64 URL Encoding/Decoding**: Converts between ArrayBuffer and Base64URL format
2. **Credential Registration**: Handles the WebAuthn credential creation process
3. **Credential Authentication**: Handles the WebAuthn assertion process
4. **Error Handling**: Manages and logs WebAuthn errors

## Security Considerations

-   WebAuthn is designed to be phishing-resistant by binding credentials to specific origins
-   User verification (PIN/biometric) can be required for high-security operations
-   Attestation can be used to verify the authenticity of authenticator devices
-   The package includes protection against replay attacks

## Browser Compatibility

WebAuthn is supported in all major modern browsers:

-   Chrome 67+
-   Firefox 60+
-   Safari 13+
-   Edge 18+

Mobile support:

-   iOS 13+
-   Android 7+ with Google Play Services

## Troubleshooting

### Common Issues

1. **"navigator.credentials is undefined"**: The browser doesn't support WebAuthn or the page isn't served over HTTPS.
2. **"SecurityError"**: The origin or relying party ID configuration is incorrect or the request is not made from a secure context.
3. **"Not allowed error"**: The user rejected the request or the authenticator is already registered.

### SSL Requirements

WebAuthn requires HTTPS in production. For local development, localhost is considered a secure context by most browsers.

## Contributing

Contributions are welcome! Please feel free to submit a pull request.

## License

This package is open-sourced software licensed under the [MIT license](LICENSE.md).
