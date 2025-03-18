<?php

namespace Scriptoshi\LivewireWebauthn;

use Illuminate\Support\Facades\Blade;
use Illuminate\Support\ServiceProvider;
use Livewire\Livewire;
use Scriptoshi\LivewireWebauthn\Http\Livewire\WebAuthnChallenge;
use Scriptoshi\LivewireWebauthn\Http\Livewire\WebAuthnManagement;

class WebAuthnServiceProvider extends ServiceProvider
{
    /**
     * Register services.
     */
    public function register(): void
    {
        $this->mergeConfigFrom(
            __DIR__ . '/../config/webauthn.php',
            'webauthn'
        );

        $this->app->singleton('webauthn', function ($app) {
            return new WebAuthnManager();
        });
    }

    /**
     * Bootstrap services.
     */
    public function boot(): void
    {
        // Only register routes if WebAuthn is enabled
        if ($this->app->make('config')->get('webauthn.enabled', false)) {
            $this->loadRoutesFrom(__DIR__ . '/../routes/web.php');
        }

        $this->loadViewsFrom(__DIR__ . '/../resources/views', 'webauthn');

        $this->loadMigrationsFrom(__DIR__ . '/../database/migrations');

        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__ . '/../config/webauthn.php' => config_path('webauthn.php'),
            ], 'config');

            $this->publishes([
                __DIR__ . '/../resources/views' => resource_path('views/vendor/webauthn'),
            ], 'views');

            $this->publishes([
                __DIR__ . '/../database/migrations' => database_path('migrations'),
            ], 'migrations');
        }
        
        // Register Blade components
        Blade::component('webauthn::components.confirms-webauthn', 'confirms-webauthn');

        // Register Livewire components
        Livewire::component('webauthn-challenge', WebAuthnChallenge::class);
        Livewire::component('webauthn-management', WebAuthnManagement::class);
    }
}