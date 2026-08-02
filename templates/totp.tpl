{include file="frontend/components/header.tpl" pageTitle="plugins.generic.magicLogin.totp.title"}
<div class="magic-login-page">

  {* ── Form column (single-column layout) ──────────────────── *}
  <main class="magic-login-main">
    <div class="magic-login-card">

      <div class="magic-login-eyebrow{if $error} magic-login-eyebrow-err{/if}">{translate key="plugins.generic.magicLogin.totp.section"}</div>
      <h1 class="magic-login-title">{translate key="plugins.generic.magicLogin.totp.heading"}</h1>
      <p class="magic-login-sub">{translate key="plugins.generic.magicLogin.totp.help"}</p>

      {if $error}
        <div class="magic-login-alert magic-login-alert-err"><div>{$error|escape}</div></div>
      {/if}

      <form class="magic-login-form" method="post" action="{$totpLoginUrl|escape}" novalidate>
        {csrf}
        <div class="magic-login-field">
          <label class="magic-login-label" for="identifier">{translate key="plugins.generic.magicLogin.totp.identifierLabel"}</label>
          <input class="magic-login-input" type="text" name="identifier" id="identifier" required
            autocomplete="username"
            placeholder="{translate key="plugins.generic.magicLogin.totp.identifierPlaceholder"}">
        </div>
        <div class="magic-login-field">
          <label class="magic-login-label" for="code">{translate key="plugins.generic.magicLogin.totp.codeLabel"}</label>
          <input class="magic-login-input" type="text" name="code" id="code" required
            inputmode="numeric" pattern="[0-9]{6}" maxlength="6" autocomplete="one-time-code"
            placeholder="123456">
        </div>
        <button class="magic-login-button" type="submit">
          <span>{translate key="plugins.generic.magicLogin.totp.button"}</span>
          <span>→</span>
        </button>
      </form>

      <div class="magic-login-switch">
        <a href="{url page='login'}">← {translate key="plugins.generic.magicLogin.request.back"}</a>
        &nbsp;&middot;&nbsp;
        <a href="{url page='magicLogin' op='request'}">{translate key="plugins.generic.magicLogin.totp.useLinkInstead"}</a>
        &nbsp;&middot;&nbsp;
        <a href="{url page='magicLogin' op='webauthnLogin'}">{translate key="plugins.generic.magicLogin.request.usePasskey"}</a>
      </div>
    </div>
  </main>

</div>
{include file="frontend/components/footer.tpl"}
