<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::table('users', function (Blueprint $table) {
            $table->boolean('webauthn_enabled')
                ->after('password')
                ->default(false);
                
            $table->timestamp('webauthn_confirmed_at')
                ->after('webauthn_enabled')
                ->nullable();
        });
        
        Schema::create(config('webauthn.credentials_table', 'webauthn_credentials'), function (Blueprint $table) {
            $table->id();
            $table->foreignId('user_id')->constrained()->cascadeOnDelete();
            $table->string('credential_id', 255)->unique();
            $table->text('public_key');
            $table->string('attestation_type', 255);
            $table->text('attestation_format')->nullable();
            $table->json('authenticator_data');
            $table->string('name')->nullable(); // Friendly name for the credential
            $table->timestamp('last_used_at')->nullable();
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::table('users', function (Blueprint $table) {
            $table->dropColumn([
                'webauthn_enabled',
                'webauthn_confirmed_at',
            ]);
        });
        
        Schema::dropIfExists(config('webauthn.credentials_table', 'webauthn_credentials'));
    }
};
