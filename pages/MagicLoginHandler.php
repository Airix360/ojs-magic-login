<?php

/**
 * @file pages/MagicLoginHandler.php
 *
 * Routes:
 *   GET  /magicLogin/request           show the "email me a link" form
 *   POST /magicLogin/send              issue + email a link (always neutral response)
 *   GET  /magicLogin/confirm?token=…   prefetch-safe confirm page (NO login on GET)
 *   POST /magicLogin/login             verify + consume + establish session
 *
 * Security model summary
 * ─────────────────────
 *  • CSRF enforced unconditionally on every mutating request via
 *    PKP's checkCSRF() -- including requests from an already-logged-in
 *    session, which is what prevents login-CSRF (an attacker's own
 *    valid token being auto-submitted by a logged-in victim's browser).
 *  • Token format validated (regex) before any DB access.
 *  • Per-IP sliding-window rate limits: /send (5/10 min), /login (10/5 min).
 *  • Per-account minimum interval enforced in TokenService (independent of IP).
 *  • Neutral /send response prevents user-account enumeration.
 *  • Token verified and consumed atomically (single DB transaction) before
 *    session creation (single-use guarantee, race-safe under concurrency).
 *  • Session ID regenerated on login (anti session-fixation, SessionService).
 *  • Cache-Control: no-store + Referrer-Policy: no-referrer on /confirm (token
 *    in query string must not be cached or sent in referer).
 *  • All login events (success and failure with reason) written to error_log.
 */

namespace APP\plugins\generic\magicLogin\pages;

use APP\core\Application;
use APP\facades\Repo;
use APP\handler\Handler;
use APP\plugins\generic\magicLogin\classes\SessionService;
use APP\plugins\generic\magicLogin\classes\TokenService;
use APP\plugins\generic\magicLogin\mailables\MagicLoginLink;
use APP\template\TemplateManager;
use Illuminate\Support\Facades\Mail;
use PKP\core\Registry;
use PKP\security\authorization\ContextRequiredPolicy;
use PKP\security\Validation;

class MagicLoginHandler extends Handler
{
    /**
     * Token format: {32 lowercase hex}.{43 url-safe base64 chars}
     * Derived from bin2hex(random_bytes(16)) + '.' + base64url(random_bytes(32)) stripped of padding.
     */
    private const TOKEN_PATTERN = '/^[0-9a-f]{32}\.[A-Za-z0-9\-_]{43}$/';
    private const TOKEN_MAX_LEN = 200; // generous ceiling; real tokens are 76 chars

    // Per-IP sliding-window limits
    private const RL_SEND_MAX  = 5;   // max /send requests per IP per window
    private const RL_SEND_WIN  = 600; // 10 minutes
    private const RL_LOGIN_MAX = 10;  // max /login POST attempts per IP per window
    private const RL_LOGIN_WIN = 300; // 5 minutes

    // Minimum wall-clock duration (seconds) the email-lookup branch of /send
    // must take before responding, so a matched email (DB writes + a
    // synchronous mail send) and an unmatched one (near-instant) are not
    // distinguishable by response timing.
    private const SEND_MIN_DURATION_SEC = 0.35;

    public function authorize($request, &$args, $roleAssignments)
    {
        $this->addPolicy(new ContextRequiredPolicy($request));
        return parent::authorize($request, $args, $roleAssignments);
    }

    // ── Public endpoints ──────────────────────────────────────────────────────

    /** GET: show the "email me a link" form. */
    public function request($args, $request): void
    {
        if (Validation::isLoggedIn()) {
            $request->redirect(null, 'dashboard');
        }
        $this->plugin()->ensureEnabled($request);

        $templateMgr = TemplateManager::getManager($request);
        $this->registerAssets($templateMgr, $request);
        $templateMgr->assign('sendUrl',
            $request->getDispatcher()->url($request, Application::ROUTE_PAGE, null, 'magicLogin', 'send')
        );
        $templateMgr->display($this->plugin()->getTemplateResource('request.tpl'));
    }

    /**
     * POST: issue + email a one-time link.
     * Response is always the same neutral message to prevent account enumeration.
     */
    public function send($args, $request): void
    {
        if (!$request->isPost() || !$this->validateCsrf($request)) {
            $request->redirect(null, 'magicLogin', 'request');
        }
        $plugin = $this->plugin();
        $plugin->ensureEnabled($request);

        $ip = $this->clientIp();

        // Per-IP rate limit prevents one IP from flooding many accounts.
        if (!self::withinRateLimit('send', $ip, self::RL_SEND_MAX, self::RL_SEND_WIN)) {
            error_log("[magicLogin] SEND_RATELIMIT ip={$ip}");
            // Show the same neutral message so the IP can't confirm the limit was hit.
            $this->showNeutralSentPage($request, $plugin);
            return;
        }

        $context = $request->getContext();
        $email   = $this->sanitizeEmail((string) $request->getUserVar('email'));

        // Timed from here so the matched and unmatched branches below can be
        // normalized to the same minimum wall-clock duration (timing
        // side-channel mitigation — see SEND_MIN_DURATION_SEC).
        $branchStart = microtime(true);

        if ($email !== null) {
            $user = Repo::user()->getByEmail($email, false); // active users only
            if ($user && !$user->getDisabled()) {
                $ttl   = $plugin->ttlSeconds($context->getId());
                $token = (new TokenService())->issue($user, $ttl, $plugin->minIntervalSeconds($context->getId()));
                if ($token) {
                    if ($this->emailLink($user, $token, $context, $request, (int) round($ttl / 60))) {
                        error_log("[magicLogin] LINK_SENT user_id={$user->getId()} ip={$ip}");
                    } else {
                        error_log("[magicLogin] LINK_SEND_FAILED user_id={$user->getId()} ip={$ip}");
                    }
                }
            } else {
                $this->performDummySendWork();
            }
        } else {
            $this->performDummySendWork();
        }

        $this->normalizeSendTiming($branchStart);

        // Always identical response — no account enumeration.
        $this->showNeutralSentPage($request, $plugin);
    }

    /**
     * GET: prefetch-safe confirm page.
     * Validates the token structure and expiry but does NOT consume it.
     * Adds cache + referrer headers so the token in the URL is not leaked.
     */
    public function confirm($args, $request): void
    {
        if (Validation::isLoggedIn()) {
            $request->redirect(null, 'dashboard');
        }
        $this->plugin()->ensureEnabled($request);

        // Prevent browser/proxy caching of URLs that carry the token as a query parameter.
        header('Cache-Control: no-store, no-cache, must-revalidate, private');
        header('Pragma: no-cache');
        // Prevent the token leaking to any external URL via the Referer header.
        header('Referrer-Policy: no-referrer');
        header('X-Content-Type-Options: nosniff');

        $rawToken = (string) $request->getUserVar('token');
        $token    = $this->sanitizeToken($rawToken);
        $error    = null;

        if ($token === null) {
            // Malformed or missing — show error immediately.
            $error = __('plugins.generic.magicLogin.error.invalid');
            $token = '';
        } else {
            // Verify on GET so the user sees an expiry error early (prefetch-safe:
            // verify() is read-only and does not consume the token).
            $user = (new TokenService())->verify($token);
            if (!$user) {
                $error = __('plugins.generic.magicLogin.error.invalid');
                $token = ''; // don't put an invalid token into the form
            }
        }

        $templateMgr = TemplateManager::getManager($request);
        $this->registerAssets($templateMgr, $request);
        $templateMgr->assign([
            'token'    => $token,
            'loginUrl' => $request->getDispatcher()->url($request, Application::ROUTE_PAGE, null, 'magicLogin', 'login'),
            'error'    => $error,
        ]);
        $templateMgr->display($this->plugin()->getTemplateResource('confirm.tpl'));
    }

    /**
     * POST: atomically verify + consume the token, then establish the session.
     * Verification and consumption happen in a single DB transaction (see
     * TokenService::verifyAndConsume()) so concurrent requests presenting the
     * same token cannot both succeed, and consumption happens before session
     * creation so a failure in session setup does not leave a live token that
     * could be replayed.
     */
    public function login($args, $request): void
    {
        if (!$request->isPost() || !$this->validateCsrf($request)) {
            $request->redirect(null, 'magicLogin', 'request');
        }
        $this->plugin()->ensureEnabled($request);

        $ip = $this->clientIp();

        // Per-IP rate limit on verify attempts.
        if (!self::withinRateLimit('login', $ip, self::RL_LOGIN_MAX, self::RL_LOGIN_WIN)) {
            error_log("[magicLogin] LOGIN_RATELIMIT ip={$ip}");
            $this->showConfirmError($request, __('plugins.generic.magicLogin.error.rateLimit'));
            return;
        }

        $token = $this->sanitizeToken((string) $request->getUserVar('token'));

        if ($token === null) {
            error_log("[magicLogin] LOGIN_FAIL ip={$ip} reason=malformed_token");
            $this->showConfirmError($request, __('plugins.generic.magicLogin.error.invalid'));
            return;
        }

        $service = new TokenService();
        // Verify and consume atomically (single transaction): guarantees a
        // token can be turned into a live session at most once, even under
        // concurrent requests presenting the same token.
        $user = $service->verifyAndConsume($token);

        if (!$user) {
            error_log("[magicLogin] LOGIN_FAIL ip={$ip} reason=invalid_or_expired_token");
            $this->showConfirmError($request, __('plugins.generic.magicLogin.error.invalid'));
            return;
        }

        if (SessionService::establishSession($user, 'magicLogin')) {
            error_log("[magicLogin] LOGIN_SUCCESS user_id={$user->getId()} ip={$ip}");
            $request->redirect(null, 'dashboard');
        }

        // Session establishment returned false (account disabled between token issue and use).
        error_log("[magicLogin] LOGIN_FAIL ip={$ip} user_id={$user->getId()} reason=session_failed");
        $request->redirect(null, 'magicLogin', 'request');
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    private function showNeutralSentPage($request, $plugin): void
    {
        $templateMgr = TemplateManager::getManager($request);
        $this->registerAssets($templateMgr, $request);
        $templateMgr->assign('neutralMessage', __('plugins.generic.magicLogin.request.sent'));
        $templateMgr->display($plugin->getTemplateResource('request.tpl'));
    }

    private function showConfirmError($request, string $message): void
    {
        $templateMgr = TemplateManager::getManager($request);
        $this->registerAssets($templateMgr, $request);
        $templateMgr->assign('error', $message);
        $templateMgr->display($this->plugin()->getTemplateResource('confirm.tpl'));
    }

    /**
     * Equivalent-cost dummy work for the "no match" branch of /send: performs
     * the same shape of work as TokenService::issue() (random byte generation
     * + hashing) without touching the database, so a profiler/timer can't
     * trivially distinguish "no account" from "account found, doing real work".
     */
    private function performDummySendWork(): void
    {
        $dummySelector = bin2hex(random_bytes(16));
        $dummyVerifier = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
        hash('sha256', $dummyVerifier . $dummySelector);
    }

    /**
     * Pads the elapsed time of the /send email-lookup branch up to
     * SEND_MIN_DURATION_SEC, so neither branch returns fast enough to leak
     * whether the submitted email matched an account.
     */
    private function normalizeSendTiming(float $branchStart): void
    {
        $elapsed   = microtime(true) - $branchStart;
        $remaining = self::SEND_MIN_DURATION_SEC - $elapsed;
        if ($remaining > 0) {
            usleep((int) round($remaining * 1_000_000));
        }
    }

    /**
     * Validate an email address. Returns the trimmed, validated email or null.
     * RFC 5321 caps addresses at 254 characters.
     */
    private function sanitizeEmail(string $raw): ?string
    {
        $email = trim($raw);
        if ($email === '' || strlen($email) > 254) {
            return null;
        }
        return filter_var($email, FILTER_VALIDATE_EMAIL) !== false ? $email : null;
    }

    /**
     * Validate a magic-link token string.
     * Expected: 32 lowercase hex chars, a literal dot, 43 url-safe base64 chars.
     * Returns the token unchanged on success, null on failure.
     */
    private function sanitizeToken(string $raw): ?string
    {
        $token = trim($raw);
        if ($token === '' || strlen($token) > self::TOKEN_MAX_LEN) {
            return null;
        }
        return preg_match(self::TOKEN_PATTERN, $token) === 1 ? $token : null;
    }

    /**
     * File-based sliding-window per-IP rate limiter.
     * Stores per-action hit timestamps in cache/_rl/ml_{action}_{ip}.json.
     * Returns true if the request is within the limit, false if it is exceeded.
     *
     * The entire read-modify-write cycle (read hits, purge stale ones, count,
     * decide, append, write) is held under a single exclusive flock so two
     * concurrent requests from the same IP cannot both read the same stale
     * hit-count and both pass the check.
     */
    private static function withinRateLimit(string $action, string $ip, int $max, int $windowSecs): bool
    {
        $dir = BASE_SYS_DIR . '/cache/_rl';
        if (!is_dir($dir)) {
            @mkdir($dir, 0755, true);
        }
        // Sanitize key components so there are no path traversal or special chars.
        $safeAction = preg_replace('/[^a-z]/i', '', $action);
        $safeIp     = preg_replace('/[^0-9a-fA-F.:]/i', '_', $ip);
        $file       = "{$dir}/ml_{$safeAction}_{$safeIp}.json";

        $handle = @fopen($file, 'c+');
        if ($handle === false) {
            // Cannot open the counter file at all — fail open rather than
            // block all logins on a filesystem hiccup.
            return true;
        }

        try {
            if (!flock($handle, LOCK_EX)) {
                return true;
            }

            $now = time();
            $raw = stream_get_contents($handle);
            $hits = is_string($raw) && $raw !== '' ? (json_decode($raw, true) ?: []) : [];
            // Purge hits that have slid out of the window.
            $hits = array_values(array_filter($hits, static fn($t) => is_int($t) && $t > $now - $windowSecs));

            if (count($hits) >= $max) {
                flock($handle, LOCK_UN);
                return false;
            }
            $hits[] = $now;

            ftruncate($handle, 0);
            rewind($handle);
            fwrite($handle, json_encode($hits));
            fflush($handle);
            flock($handle, LOCK_UN);
            return true;
        } finally {
            fclose($handle);
        }
    }

    /** Get the client IP, validated against FILTER_VALIDATE_IP. */
    private function clientIp(): string
    {
        return filter_var($_SERVER['REMOTE_ADDR'] ?? '', FILTER_VALIDATE_IP) ?: '0.0.0.0';
    }

    /** Returns true only if the email was actually handed off to the mailer without error. */
    private function emailLink($user, string $token, $context, $request, int $expiryMinutes): bool
    {
        try {
            $magicUrl = $request->getDispatcher()->url(
                $request, Application::ROUTE_PAGE, null,
                'magicLogin', 'confirm', null, ['token' => $token]
            );

            // Load subject + body from the DB template (customisable in Settings › Emails).
            // Falls back to plain-text content so the email is never silently dropped.
            $template = Repo::emailTemplate()->getByKey($context->getId(), MagicLoginLink::EMAIL_KEY);
            $subject  = $template
                ? $template->getLocalizedData('subject')
                : 'Your sign-in link for {$contextName}';
            $body     = $template
                ? $template->getLocalizedData('body')
                : '<p>Hi {$recipientName},</p>'
                  . '<p>Click the link below to sign in to {$contextName}. '
                  . 'It expires in {$expiryMinutes} minutes and works once only.</p>'
                  . '<p><a href="{$magicUrl}">{$magicUrl}</a></p>'
                  . '<p>If you did not request this, you can safely ignore this email.</p>';

            $mailable = new MagicLoginLink($context);
            $mailable
                ->recipients([$user])
                ->from($context->getData('contactEmail'), $context->getData('contactName'))
                ->subject($subject)
                ->body($body)
                ->addData([
                    'recipientName' => $user->getFullName(),
                    'contextName'   => $context->getLocalizedData('name'),
                    'magicUrl'      => $magicUrl,
                    'expiryMinutes' => $expiryMinutes,
                ]);
            Mail::send($mailable);
            return true;
        } catch (\Throwable $e) {
            error_log('[magicLogin] link email failed: ' . $e->getMessage());
            return false;
        }
    }

    /**
     * CSRF must be present unconditionally, regardless of login state.
     * Skipping the check for already-logged-in requesters would allow a
     * login-CSRF attack: an attacker who owns a valid token for their own
     * account hosts a page that auto-submits POST /magicLogin/login with
     * that token; a logged-in victim's browser would send it with valid
     * cookies and no CSRF check, silently switching the victim's session
     * into the attacker's account.
     */
    private function validateCsrf($request): bool
    {
        return $request->checkCSRF();
    }

    private function registerAssets(TemplateManager $templateMgr, $request): void
    {
        $templateMgr->addStyleSheet(
            'magicLogin',
            $request->getBaseUrl() . '/' . $this->plugin()->getPluginPath() . '/css/magicLogin.css'
        );
    }

    private function plugin()
    {
        return Registry::get('plugin');
    }
}
