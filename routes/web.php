<?php

use Illuminate\Support\Facades\Route;
use Scriptoshi\LivewireWebauthn\Http\Middleware\WebAuthn;

// Route for handling the WebAuthn challenge during login
Route::middleware(['web', 'guest'])->group(function () {
    Route::get('/webauthn-challenge', function () {
        if (!session()->has('login.id')) {
            return redirect()->route('login');
        }
        return view('webauthn::livewire.challenge-page');
    })->name('webauthn.challenge');
});

// Register the middleware to intercept login attempts
Route::middleware(['web'])->group(function () {
    // This route will handle the authentication attempt and redirect to WebAuthn if needed
    Route::post('/webauthn/login', function () {
        // The middleware will handle redirecting to WebAuthn challenge if needed
        return redirect()->intended(route('dashboard'));
    })->middleware(WebAuthn::class)->name('webauthn.login');
});
