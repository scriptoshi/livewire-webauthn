<?php

return [

    /*
    |--------------------------------------------------------------------------
    | WebAuthn Authentication Enable
    |--------------------------------------------------------------------------
    |
    | This option controls if WebAuthn authentication is enabled for your
    | application. When set to "true", users can register WebAuthn
    | credentials for their accounts.
    |
    */

    'enabled' => env('WEBAUTHN_ENABLED', true),

    /*
    |--------------------------------------------------------------------------
    | WebAuthn Relying Party Information
    |--------------------------------------------------------------------------
    |
    | These settings define your application as a WebAuthn Relying Party.
    | The name is shown to users during registration/authentication,
    | and the id should match your application's domain.
    |
    */
    
    'relying_party' => [
        'name' => env('WEBAUTHN_RP_NAME', config('app.name')),
        'id' => env('WEBAUTHN_RP_ID', parse_url(config('app.url'), PHP_URL_HOST)),
    ],

    /*
    |--------------------------------------------------------------------------
    | WebAuthn Credential Storage Table
    |--------------------------------------------------------------------------
    |
    | This is the database table name where WebAuthn credentials
    | will be stored. You can change this if needed to avoid
    | conflicts with existing tables.
    |
    */

    'credentials_table' => env('WEBAUTHN_CREDENTIALS_TABLE', 'webauthn_credentials'),

    /*
    |--------------------------------------------------------------------------
    | WebAuthn Authentication Timeout
    |--------------------------------------------------------------------------
    |
    | This configuration option determines how long (in seconds) a successful
    | WebAuthn authentication is valid before requiring re-verification.
    | Default is 15 minutes (900 seconds).
    |
    */

    'timeout' => env('WEBAUTHN_TIMEOUT', 900),
    
    /*
    |--------------------------------------------------------------------------
    | WebAuthn Attestation Conveyance
    |--------------------------------------------------------------------------
    |
    | This option defines how the attestation data is conveyed during credential
    | registration. Options are 'none', 'indirect', 'direct', or 'enterprise'.
    | For most applications, 'none' or 'indirect' is recommended.
    |
    */
    
    'attestation_conveyance' => env('WEBAUTHN_ATTESTATION_CONVEYANCE', 'none'),
    
    /*
    |--------------------------------------------------------------------------
    | WebAuthn User Verification Requirement
    |--------------------------------------------------------------------------
    |
    | This option defines whether user verification is required during
    | authentication. Options are 'required', 'preferred', or 'discouraged'.
    | Use 'required' for higher security (forces PIN/biometric).
    |
    */
    
    'user_verification' => env('WEBAUTHN_USER_VERIFICATION', 'preferred'),
    
    /*
    |--------------------------------------------------------------------------
    | Allowed Algorithms
    |--------------------------------------------------------------------------
    |
    | The algorithms that are allowed for credential creation.
    | Common algorithms include ES256 (-7), RS256 (-257), and EdDSA (-8).
    |
    */
    
    'algorithms' => [-7, -257, -8],
];
