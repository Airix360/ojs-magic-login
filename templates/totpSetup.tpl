{include file="frontend/components/header.tpl" pageTitle="plugins.generic.magicLogin.totpSetup.title"}
<div class="magic-login-page">

  <main class="magic-login-main">
    <div class="magic-login-card">

      <div class="magic-login-eyebrow{if $error} magic-login-eyebrow-err{/if}">{translate key="plugins.generic.magicLogin.totpSetup.section"}</div>
      <h1 class="magic-login-title">{translate key="plugins.generic.magicLogin.totpSetup.heading"}</h1>

      {if $success}
        <div class="magic-login-alert magic-login-alert-ok"><div>{$success|escape}</div></div>
      {/if}
      {if $error}
        <div class="magic-login-alert magic-login-alert-err"><div>{$error|escape}</div></div>
      {/if}

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

        {* No QR image is rendered here — see README for the reasoning:
           drawing a scannable QR code from scratch (matrix layout + Reed-
           Solomon error correction) is significant complexity for a plugin
           that otherwise adds zero dependencies. Instead: a tappable
           otpauth:// link (works when opened on the same device as the
           authenticator app) plus the raw secret for manual entry, which
           every authenticator app supports. *}
        <div class="magic-login-field">
          <label class="magic-login-label">{translate key="plugins.generic.magicLogin.totpSetup.uriLabel"}</label>
          <p><a href="{$totpUri|escape}" style="word-break:break-all;">{$totpUri|escape}</a></p>
        </div>
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
  </main>

</div>
{include file="frontend/components/footer.tpl"}
