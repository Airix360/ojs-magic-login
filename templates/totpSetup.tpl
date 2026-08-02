{include file="frontend/components/header.tpl" pageTitle="plugins.generic.magicLogin.totpSetup.title"}
<div class="magic-login-page">

  <main class="magic-login-main">

    {if $success}
      <div class="magic-login-alert magic-login-alert-ok"><div>{$success|escape}</div></div>
    {/if}
    {if $error}
      <div class="magic-login-alert magic-login-alert-err"><div>{$error|escape}</div></div>
    {/if}

    {* ── Authenticator app (TOTP) ─────────────────────────────────────── *}
    <div class="magic-login-card">

      <div class="magic-login-eyebrow">{translate key="plugins.generic.magicLogin.totpSetup.section"}</div>
      <h1 class="magic-login-title">{translate key="plugins.generic.magicLogin.totpSetup.heading"}</h1>

      {if $totpEnabled}

        <p class="magic-login-sub">{translate key="plugins.generic.magicLogin.totpSetup.enabledHelp"}</p>

        <form class="magic-login-form" method="post" action="{$totpDisableUrl|escape}">
          {csrf}
          <div class="magic-login-field">
            <label class="magic-login-label" for="password">{translate key="plugins.generic.magicLogin.totpSetup.passwordLabel"}</label>
            <input class="magic-login-input" type="password" name="password" id="password" required autocomplete="current-password">
          </div>
          <button class="magic-login-button" type="submit">
            <span>{translate key="plugins.generic.magicLogin.totpSetup.disableButton"}</span>
          </button>
        </form>

      {else}

        <p class="magic-login-sub">{translate key="plugins.generic.magicLogin.totpSetup.setupHelp"}</p>

        {* QR rendered client-side via vendored davidshimjs/qrcodejs (MIT,
           no dependencies) — see README for why this uses a small,
           well-established existing library instead of a from-scratch QR
           encoder. Falls back gracefully to the tappable link below if JS
           is unavailable. *}
        <div class="magic-login-field">
          <div id="magic-login-qr" style="display:inline-block;padding:12px;background:#fff;border:1px solid rgba(0,0,0,.08);border-radius:4px;"></div>
        </div>
        <div class="magic-login-field">
          <label class="magic-login-label">{translate key="plugins.generic.magicLogin.totpSetup.uriLabel"}</label>
          <p><a href="{$totpUri|escape}" style="word-break:break-all;">{$totpUri|escape}</a></p>
        </div>
        <script>
          document.addEventListener('DOMContentLoaded', function () {ldelim}
            if (typeof QRCode === 'undefined') {ldelim} return; {rdelim}
            new QRCode(document.getElementById('magic-login-qr'), {ldelim}
              text: "{$totpUri|escape:'javascript'}",
              width: 200,
              height: 200,
              correctLevel: QRCode.CorrectLevel.M
            {rdelim});
          {rdelim});
        </script>
        <div class="magic-login-field">
          <label class="magic-login-label">{translate key="plugins.generic.magicLogin.totpSetup.secretLabel"}</label>
          <p style="font-family:monospace;font-size:1.1em;letter-spacing:0.05em;">{$totpSecret|escape}</p>
        </div>

        <form class="magic-login-form" method="post" action="{$totpConfirmUrl|escape}" novalidate>
          {csrf}
          <div class="magic-login-field">
            <label class="magic-login-label" for="code">{translate key="plugins.generic.magicLogin.totpSetup.codeLabel"}</label>
            <input class="magic-login-input" type="text" name="code" id="code" required
              inputmode="numeric" pattern="[0-9]{6}" maxlength="6" autocomplete="one-time-code"
              placeholder="123456">
          </div>
          <button class="magic-login-button" type="submit">
            <span>{translate key="plugins.generic.magicLogin.totpSetup.confirmButton"}</span>
          </button>
        </form>

      {/if}
    </div>

    {* ── Passkeys (WebAuthn) ──────────────────────────────────────────── *}
    <div class="magic-login-card" style="margin-top:1.5rem;">

      <div class="magic-login-eyebrow">{translate key="plugins.generic.magicLogin.webauthn.section"}</div>
      <h1 class="magic-login-title">{translate key="plugins.generic.magicLogin.webauthn.heading"}</h1>
      <p class="magic-login-sub">{translate key="plugins.generic.magicLogin.webauthn.help"}</p>

      <div id="webauthn-status" class="magic-login-alert magic-login-alert-err" style="display:none;"></div>

      {if $webauthnCredentials}
        <table style="width:100%;border-collapse:collapse;margin:1rem 0;">
          <thead>
            <tr style="text-align:left;border-bottom:1px solid rgba(0,0,0,.1);">
              <th style="padding:0.5rem 0;">{translate key="plugins.generic.magicLogin.webauthn.table.name"}</th>
              <th style="padding:0.5rem 0;">{translate key="plugins.generic.magicLogin.webauthn.table.added"}</th>
              <th style="padding:0.5rem 0;">{translate key="plugins.generic.magicLogin.webauthn.table.lastUsed"}</th>
              <th style="padding:0.5rem 0;"></th>
            </tr>
          </thead>
          <tbody>
            {foreach from=$webauthnCredentials item=cred}
              <tr style="border-bottom:1px solid rgba(0,0,0,.05);">
                <td style="padding:0.5rem 0;">{if $cred.nickname}{$cred.nickname|escape}{else}{translate key="plugins.generic.magicLogin.webauthn.unnamed"}{/if}</td>
                <td style="padding:0.5rem 0;">{$cred.createdAt|escape}</td>
                <td style="padding:0.5rem 0;">{if $cred.lastUsedAt}{$cred.lastUsedAt|escape}{else}—{/if}</td>
                <td style="padding:0.5rem 0;text-align:right;">
                  <form method="post" action="{$webauthnDeleteUrl|escape}" onsubmit="return confirm('{translate key="plugins.generic.magicLogin.webauthn.confirmRemove"}');" style="display:inline-flex;gap:0.5rem;align-items:center;">
                    {csrf}
                    <input type="hidden" name="credentialRecordId" value="{$cred.id|escape}">
                    <input class="magic-login-input" type="password" name="password" required autocomplete="current-password"
                      placeholder="{translate key="plugins.generic.magicLogin.totpSetup.passwordLabel"}" style="width:10rem;padding:0.35rem;">
                    <button class="magic-login-button" type="submit" style="padding:0.35rem 0.75rem;">{translate key="plugins.generic.magicLogin.webauthn.removeButton"}</button>
                  </form>
                </td>
              </tr>
            {/foreach}
          </tbody>
        </table>
      {else}
        <p class="magic-login-sub">{translate key="plugins.generic.magicLogin.webauthn.none"}</p>
      {/if}

      {if $webauthnCanAddMore}
        <div class="magic-login-field">
          <label class="magic-login-label" for="webauthn-nickname">{translate key="plugins.generic.magicLogin.webauthn.nicknameLabel"}</label>
          <input class="magic-login-input" type="text" id="webauthn-nickname" maxlength="191"
            placeholder="{translate key="plugins.generic.magicLogin.webauthn.nicknamePlaceholder"}">
        </div>
        <button class="magic-login-button" type="button" id="webauthn-add-btn"
          data-options-url="{$webauthnRegisterOptionsUrl|escape}"
          data-verify-url="{$webauthnRegisterVerifyUrl|escape}">
          <span>{translate key="plugins.generic.magicLogin.webauthn.addButton"}</span>
        </button>
      {/if}
    </div>

  </main>

</div>
{include file="frontend/components/footer.tpl"}
