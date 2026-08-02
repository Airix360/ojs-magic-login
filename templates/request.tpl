{include file="frontend/components/header.tpl" pageTitle="plugins.generic.magicLogin.request.title"}
<div class="magic-login-page">

  {* ── Form column (single-column layout) ──────────────────── *}
  <main class="magic-login-main">
    <div class="magic-login-card">

      {if $neutralMessage}

        <div class="magic-login-eyebrow magic-login-eyebrow-ok">{translate key="plugins.generic.magicLogin.request.section"}</div>
        <h1 class="magic-login-title">{translate key="plugins.generic.magicLogin.request.title"}</h1>
        <div class="magic-login-alert magic-login-alert-ok"><div>{$neutralMessage|escape}</div></div>
        <p class="magic-login-sub">{translate key="plugins.generic.magicLogin.request.sentNotice"}</p>
        <div class="magic-login-switch">
          <a href="{url page='login'}">← {translate key="plugins.generic.magicLogin.request.back"}</a>
        </div>

      {else}

        <div class="magic-login-eyebrow">{translate key="plugins.generic.magicLogin.request.section"}</div>
        <h1 class="magic-login-title">{translate key="plugins.generic.magicLogin.request.heading"}</h1>
        <p class="magic-login-sub">{translate key="plugins.generic.magicLogin.request.help"}</p>

        <form class="magic-login-form" id="magicRequestForm" method="post" action="{$sendUrl|escape}" novalidate>
          {csrf}
          <div class="magic-login-field">
            <label class="magic-login-label" for="email">{translate key="user.email"}</label>
            <input class="magic-login-input" type="email" name="email" id="email" required
              autocomplete="email"
              placeholder="{translate key="plugins.generic.magicLogin.request.emailPlaceholder"}">
          </div>
          <button class="magic-login-button" type="submit">
            <span>{translate key="plugins.generic.magicLogin.request.button"}</span>
            <span>→</span>
          </button>
        </form>

        <div class="magic-login-switch">
          <a href="{url page='login'}">← {translate key="plugins.generic.magicLogin.request.back"}</a>
          &nbsp;&middot;&nbsp;
          <a href="{url page='magicLogin' op='totp'}">{translate key="plugins.generic.magicLogin.request.useTotp"}</a>
          &nbsp;&middot;&nbsp;
          <a href="{url page='magicLogin' op='webauthnLogin'}">{translate key="plugins.generic.magicLogin.request.usePasskey"}</a>
        </div>

      {/if}
    </div>
  </main>

</div>
{include file="frontend/components/footer.tpl"}
