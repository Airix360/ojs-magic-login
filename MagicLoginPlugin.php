<?php

/**
 * @file MagicLoginPlugin.php
 *
 * Distributed under the GNU GPL v3.
 *
 * @class MagicLoginPlugin
 * @brief Passwordless sign-in for OJS 3.5 — Phase 1: email magic links.
 */

namespace APP\plugins\generic\magicLogin;

use APP\core\Application;
use APP\facades\Repo;
use APP\plugins\generic\magicLogin\mailables\MagicLoginLink;
use APP\plugins\generic\magicLogin\pages\MagicLoginHandler;
use Illuminate\Support\Facades\DB;
use PKP\core\JSONMessage;
use PKP\core\Registry;
use PKP\linkAction\LinkAction;
use PKP\linkAction\request\AjaxModal;
use PKP\plugins\GenericPlugin;
use PKP\plugins\Hook;

require_once(dirname(__FILE__) . '/WebAuthnCredentialsTableMigration.php');

class MagicLoginPlugin extends GenericPlugin
{
    /**
     * Plugin setting (per-context) holding a JSON-encoded, capped, newest-first
     * list of recent magic-login events for the "Recent activity" panel shown
     * in Settings. Purely for admin visibility — never read by any security
     * decision, so a lost update under concurrent writes is a cosmetic
     * (not a security) issue.
     */
    public const RECENT_ATTEMPTS_SETTING = 'magicLoginRecentAttempts';
    public const RECENT_ATTEMPTS_MAX     = 20;

    public function register($category, $path, $mainContextId = null)
    {
        $success = parent::register($category, $path, $mainContextId);
        if (!$success) {
            return false;
        }

        // Rename any legacy versions row recorded under the wrong product key
        // ('ojs2') so that OJS version-tracking stays consistent after the
        // 1.0.0 → 1.1.0 fix.  Idempotent: no-op once the row is correct.
        $this->migrateVersionRecord();

        if (!$this->getEnabled($mainContextId)) {
            return true;
        }

        Hook::add('LoadHandler',           [$this, 'setupHandler']);
        Hook::add('TemplateManager::display', [$this, 'addLoginLink']);
        // The profile Password tab is fetched as an AJAX fragment
        // (controllers/tab/user/ProfileTabHandler::changePassword() calls
        // Form::fetch(), never TemplateManager::display()), so this must hook
        // 'TemplateManager::fetch', not 'TemplateManager::display' — the
        // latter never fires for this template and silently no-ops.
        Hook::add('TemplateManager::fetch', [$this, 'addTotpAccountLink']);
        Hook::add('Mailer::Mailables',     [$this, 'addMailable']);

        // Ensure the email template is installed for the current context.
        // installEmailTemplates() with skipExisting=true is idempotent.
        $this->ensureEmailTemplates();

        return true;
    }

    // ── Routing ─────────────────────────────────────────────────────────────

    public function setupHandler(string $hookName, array $args): bool
    {
        if ($args[0] === 'magicLogin') {
            Registry::set('plugin', $this);
            $handler = &$args[3];
            $handler = new MagicLoginHandler();
            return Hook::ABORT;
        }
        return Hook::CONTINUE;
    }

    // ── Mailable registration ────────────────────────────────────────────────

    /**
     * Push MagicLoginLink into OJS's mailable collection so it appears
     * in Settings › Emails and can be customised by journal managers.
     * Must return void (matching the OJS 3.5 hook signature).
     */
    public function addMailable(string $hookName, array $args): void
    {
        $args[0]->push(MagicLoginLink::class);
    }

    /**
     * @copydoc Plugin::getInstallEmailTemplatesFile()
     */
    public function getInstallEmailTemplatesFile()
    {
        return $this->getPluginPath() . '/emailTemplates.xml';
    }

    /**
     * @copydoc Plugin::getInstallMigration()
     */
    public function getInstallMigration()
    {
        return new WebAuthnCredentialsTableMigration();
    }

    /**
     * Install the MAGIC_LOGIN_LINK email template the first time this plugin
     * is activated on a context that does not yet have it.
     */
    private function ensureEmailTemplates(): void
    {
        try {
            $request = Application::get()->getRequest();
            $context = $request->getContext();
            if (!$context) {
                return;
            }
            $existing = Repo::emailTemplate()->getByKey($context->getId(), MagicLoginLink::EMAIL_KEY);
            if ($existing) {
                return;
            }
            $this->addLocaleData();
            Repo::emailTemplate()->dao->installEmailTemplates(
                $this->getInstallEmailTemplatesFile(),
                [],
                null,
                true
            );
        } catch (\Throwable $e) {
            error_log('[magicLogin] email template install failed: ' . $e->getMessage());
        }
    }

    // ── DB migration ─────────────────────────────────────────────────────────

    /** Site-level plugin setting flag recording that migrateVersionRecord() has already run. */
    private const SETTING_VERSION_RECORD_MIGRATED = 'versionRecordMigrated';

    /**
     * v1.0.0 shipped with <application>ojs2</application> in version.xml,
     * causing OJS to record product='ojs2' in the versions table instead of
     * the correct 'magicLogin'.  Rename the row so version tracking and the
     * plugin list work correctly on existing installations.
     *
     * This is a one-time fix-up: once it has run (successfully or not, so a
     * transient failure doesn't retry forever either) it is gated behind a
     * persisted site-level setting so it does not run again on every
     * subsequent page load site-wide.
     */
    private function migrateVersionRecord(): void
    {
        // Site-level (context null) since the versions table itself is site-wide.
        // plugin_settings.context_id has a FK to journals(journal_id), which has
        // no row for id 0 — only NULL (site-wide) or a real journal id are valid.
        if ($this->getSetting(null, self::SETTING_VERSION_RECORD_MIGRATED)) {
            return;
        }

        try {
            $alreadyCorrect = DB::table('versions')
                ->where('product_type', 'plugins.generic')
                ->where('product', 'magicLogin')
                ->exists();

            if (!$alreadyCorrect) {
                DB::table('versions')
                    ->where('product_type', 'plugins.generic')
                    ->where('product', 'ojs2')
                    ->where('product_class_name', 'MagicLoginPlugin')
                    ->update(['product' => 'magicLogin']);
            }
        } catch (\Throwable $e) {
            error_log('[magicLogin] migrateVersionRecord failed: ' . $e->getMessage());
        } finally {
            $this->updateSetting(null, self::SETTING_VERSION_RECORD_MIGRATED, true, 'bool');
        }
    }

    // ── Login page link ──────────────────────────────────────────────────────

    public function addLoginLink(string $hookName, array $args): bool
    {
        $template = $args[1];
        if (!str_contains($template, 'userLogin.tpl') && !str_contains($template, 'openidLogin.tpl')) {
            return Hook::CONTINUE;
        }
        $request = Application::get()->getRequest();
        $context = $request->getContext();
        if (!$context) {
            return Hook::CONTINUE;
        }
        /** @var \APP\template\TemplateManager $templateMgr */
        $templateMgr = $args[0];
        // Backward-compatible: themes may render this variable themselves.
        $templateMgr->assign('magicLoginRequestUrl',
            $request->getDispatcher()->url($request, Application::ROUTE_PAGE, null, 'magicLogin', 'request')
        );
        // Theme-agnostic auto-injection: insert the button straight into the
        // rendered login form via an output filter, so a fresh install needs
        // NO theme template edits. The default OJS login template has no slot
        // for plugin content, so we post-process the HTML.
        $templateMgr->registerFilter('output', [$this, 'injectLoginButton']);
        return Hook::CONTINUE;
    }

    /**
     * Smarty output filter: inject the magic-login button into the rendered
     * sign-in form. Theme-agnostic; no template edits required.
     */
    public function injectLoginButton(string $output, $templateMgr): string
    {
        // Skip if a theme already rendered the link, or we already injected.
        if (str_contains($output, 'magic-login-inject') || str_contains($output, 'magicLogin/request')) {
            return $output;
        }
        $request = Application::get()->getRequest();
        $context = $request->getContext();
        if (!$context || !$this->getSetting($context->getId(), 'enabled')) {
            return $output;
        }
        $url   = $request->getDispatcher()->url($request, Application::ROUTE_PAGE, null, 'magicLogin', 'request');
        $label = htmlspecialchars((string) __('plugins.generic.magicLogin.login.button'), ENT_QUOTES);
        $block = '<div class="magic-login-inject" style="margin:1rem 0 0;padding-top:1rem;border-top:1px solid rgba(0,0,0,.08);text-align:center;">'
               . '<a href="' . htmlspecialchars($url, ENT_QUOTES) . '" class="magic-login-inject__link" style="display:inline-block;font-weight:600;text-decoration:underline;">'
               . $label . '</a></div>';

        // Preferred: insert just before the closing </form> of the sign-in form.
        $pattern = '/(<form\b[^>]*action="[^"]*\/login\/signIn[^"]*"[^>]*>.*?)(<\/form>)/is';
        if (preg_match($pattern, $output)) {
            return preg_replace($pattern, '$1' . $block . '$2', $output, 1);
        }
        // Fallback: after the first closing form tag on the page.
        $pos = stripos($output, '</form>');
        if ($pos !== false) {
            return substr($output, 0, $pos + 7) . $block . substr($output, $pos + 7);
        }
        return $output;
    }

    /**
     * Best-effort injection of a "Manage two-factor sign-in" link into the
     * logged-in user's own Profile › Password tab, so TOTP setup is
     * discoverable without needing a theme edit — same technique as
     * injectLoginButton(). If a theme's changePassword.tpl override doesn't
     * end in a `</form>` tag, this simply no-ops (the page is still directly
     * reachable at magicLogin/totpSetup; see README).
     */
    public function addTotpAccountLink(string $hookName, array $args): bool
    {
        // 'user/changePassword.tpl' is the actual template the Profile ›
        // Password tab renders (there is no 'userProfile.tpl' in OJS 3.5 —
        // the previous check matched nothing and this injector never fired).
        $template = $args[1];
        if (!str_contains($template, 'user/changePassword.tpl')) {
            return Hook::CONTINUE;
        }
        $request = Application::get()->getRequest();
        $context = $request->getContext();
        if (!$context || !$this->getSetting($context->getId(), 'enabled')) {
            return Hook::CONTINUE;
        }
        /** @var \APP\template\TemplateManager $templateMgr */
        $templateMgr = $args[0];
        $templateMgr->registerFilter('output', [$this, 'injectTotpAccountLink']);
        return Hook::CONTINUE;
    }

    /** Smarty output filter: inject the TOTP account-settings link into the profile page. */
    public function injectTotpAccountLink(string $output, $templateMgr): string
    {
        if (str_contains($output, 'magic-login-totp-inject') || str_contains($output, 'magicLogin/totpSetup')) {
            return $output;
        }
        $request = Application::get()->getRequest();
        $url     = $request->getDispatcher()->url($request, Application::ROUTE_PAGE, null, 'magicLogin', 'totpSetup');
        $label   = htmlspecialchars((string) __('plugins.generic.magicLogin.totpSetup.profileLink'), ENT_QUOTES);
        $block   = '<div class="magic-login-totp-inject" style="margin:1rem 0;padding:1rem;border-top:1px solid rgba(0,0,0,.08);">'
                 . '<a href="' . htmlspecialchars($url, ENT_QUOTES) . '">' . $label . '</a></div>';

        $pos = stripos($output, '</form>');
        if ($pos !== false) {
            return substr($output, 0, $pos + 7) . $block . substr($output, $pos + 7);
        }
        return $output;
    }

    // ── Feature guards + config ──────────────────────────────────────────────

    public function ensureEnabled($request): void
    {
        $context = $request->getContext();
        if (!$context || !$this->getSetting($context->getId(), 'enabled')) {
            $request->redirect(null, 'login', 'signIn');
        }
    }

    public function ttlSeconds(int $contextId): int
    {
        $minutes = (int) $this->getSetting($contextId, 'ttlMinutes');
        return ($minutes >= 1 ? $minutes : 15) * 60;
    }

    public function minIntervalSeconds(int $contextId): int
    {
        $seconds = (int) $this->getSetting($contextId, 'minIntervalSeconds');
        return $seconds >= 30 ? $seconds : 60;
    }

    // ── Settings UI ──────────────────────────────────────────────────────────

    public function getActions($request, $actionArgs)
    {
        $actions = parent::getActions($request, $actionArgs);
        if (!$this->getEnabled()) {
            return $actions;
        }
        $router = $request->getRouter();
        array_unshift($actions, new LinkAction(
            'settings',
            new AjaxModal(
                $router->url($request, null, null, 'manage', null, array_merge($actionArgs, ['verb' => 'settings'])),
                $this->getDisplayName()
            ),
            __('manager.plugins.settings')
        ));
        return $actions;
    }

    public function manage($args, $request)
    {
        if ($request->getUserVar('verb') === 'settings') {
            $templateMgr = \APP\template\TemplateManager::getManager($request);
            $templateMgr->assign('pluginName', $this->getName());
            $form = new MagicLoginSettingsForm($this);
            if ($request->getUserVar('save')) {
                $form->readInputData();
                if ($form->validate()) {
                    $form->execute();
                    return new JSONMessage(true);
                }
            } else {
                $form->initData();
            }
            return new JSONMessage(true, $form->fetch($request));
        }
        return parent::manage($args, $request);
    }

    public function getDisplayName()
    {
        return __('plugins.generic.magicLogin.displayName');
    }

    public function getDescription()
    {
        return __('plugins.generic.magicLogin.description');
    }
}
