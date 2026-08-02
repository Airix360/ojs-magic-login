<?php

/**
 * @file plugins/generic/magicLogin/WebAuthnCredentialsTableMigration.php
 *
 * Copyright (c) 2026 Hendrix Nwaokolo, Airix Media
 * Distributed under the GNU GPL v3. For full terms see the file LICENSE.
 *
 * @class WebAuthnCredentialsTableMigration
 *
 * @brief Creates `magic_login_webauthn_credentials` — one row per registered
 * passkey/security key. A user can register more than one (phone + a backup
 * security key, say), so unlike the single-secret TOTP feature (stored as
 * one user_settings row) this needs a real one-to-many table.
 */

namespace APP\plugins\generic\magicLogin;

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\Schema;
use Illuminate\Database\Schema\Blueprint;

class WebAuthnCredentialsTableMigration extends Migration
{
    public function up(): void
    {
        if (Schema::hasTable('magic_login_webauthn_credentials')) {
            return;
        }
        Schema::create('magic_login_webauthn_credentials', function (Blueprint $table) {
            $table->bigIncrements('credential_record_id');
            $table->bigInteger('user_id');
            // base64url credential ID from the authenticator; unique per
            // credential, used to look up which user is authenticating.
            $table->string('credential_id', 512)->unique();
            $table->text('public_key_pem');
            $table->integer('cose_alg');
            $table->text('transports')->nullable(); // JSON array: usb, nfc, ble, internal, hybrid
            $table->string('aaguid', 64)->nullable();
            $table->unsignedBigInteger('sign_count')->default(0);
            $table->string('nickname', 191)->nullable();
            $table->timestamp('created_at')->useCurrent();
            $table->timestamp('last_used_at')->nullable();
            $table->index(['user_id']);
        });
    }

    public function down(): void
    {
        if (Schema::hasTable('magic_login_webauthn_credentials')) {
            Schema::drop('magic_login_webauthn_credentials');
        }
    }
}
