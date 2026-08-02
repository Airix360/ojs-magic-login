{include file="frontend/components/header.tpl" pageTitle="plugins.generic.magicLogin.webauthn.login.title"}
<div class="magic-login-page">

  <main class="magic-login-main">
    <div class="magic-login-card">

      <div class="magic-login-eyebrow">{translate key="plugins.generic.magicLogin.webauthn.login.section"}</div>
      <h1 class="magic-login-title">{translate key="plugins.generic.magicLogin.webauthn.login.heading"}</h1>
      <p class="magic-login-sub">{translate key="plugins.generic.magicLogin.webauthn.login.help"}</p>

      <div id="webauthn-login-status" class="magic-login-alert magic-login-alert-err" style="display:none;"></div>

      {* Usernameless: no identifier field. The browser/authenticator lists
         whichever resident passkeys it holds for this site. *}
      <form id="webauthnLoginForm" novalidate
        data-options-url="{$webauthnLoginOptionsUrl|escape}"
        data-verify-url="{$webauthnLoginVerifyUrl|escape}">
        <button class="magic-login-button" type="submit">
          <span>{translate key="plugins.generic.magicLogin.webauthn.login.button"}</span>
          <span>→</span>
        </button>
      </form>

      <div class="magic-login-switch">
        <a href="{url page='login'}">← {translate key="plugins.generic.magicLogin.request.back"}</a>
        &nbsp;&middot;&nbsp;
        <a href="{url page='magicLogin' op='request'}">{translate key="plugins.generic.magicLogin.totp.useLinkInstead"}</a>
      </div>
    </div>
  </main>

</div>
{include file="frontend/components/footer.tpl"}
