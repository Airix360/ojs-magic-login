<?php

/**
 * @file MagicLoginSettingsForm.php
 */

namespace APP\plugins\generic\magicLogin;

use APP\core\Application;
use APP\facades\Repo;
use PKP\form\Form;
use PKP\form\validation\FormValidatorCSRF;
use PKP\form\validation\FormValidatorPost;

class MagicLoginSettingsForm extends Form
{
    /** Hard caps so an admin cannot accidentally configure insecure values. */
    private const TTL_MIN      = 1;
    private const TTL_MAX      = 120;  // minutes — 2 hours absolute ceiling
    private const TTL_DEFAULT  = 15;

    private const INTERVAL_MIN     = 30;    // seconds — prevents flooding
    private const INTERVAL_MAX     = 3600;  // seconds — 1 hour absolute ceiling
    private const INTERVAL_DEFAULT = 60;

    /** Event codes recorded by MagicLoginHandler::recordAttempt() and their locale keys. */
    private const EVENT_LABELS = [
        'LINK_SENT'         => 'plugins.generic.magicLogin.activity.event.linkSent',
        'LINK_SEND_FAILED'  => 'plugins.generic.magicLogin.activity.event.linkSendFailed',
        'SEND_RATELIMIT'    => 'plugins.generic.magicLogin.activity.event.sendRateLimited',
        'LOGIN_SUCCESS'     => 'plugins.generic.magicLogin.activity.event.loginSuccess',
        'LOGIN_FAIL'        => 'plugins.generic.magicLogin.activity.event.loginFail',
        'LOGIN_RATELIMIT'   => 'plugins.generic.magicLogin.activity.event.loginRateLimited',
    ];

    private MagicLoginPlugin $plugin;

    public function __construct(MagicLoginPlugin $plugin)
    {
        $this->plugin = $plugin;
        parent::__construct($plugin->getTemplateResource('settings.tpl'));
        $this->addCheck(new FormValidatorPost($this));
        $this->addCheck(new FormValidatorCSRF($this));
    }

    public function initData(): void
    {
        $contextId = Application::get()->getRequest()->getContext()->getId();
        $this->setData('enabled',            (bool) $this->plugin->getSetting($contextId, 'enabled'));
        $this->setData('ttlMinutes',         $this->plugin->getSetting($contextId, 'ttlMinutes') ?: self::TTL_DEFAULT);
        $this->setData('minIntervalSeconds', $this->plugin->getSetting($contextId, 'minIntervalSeconds') ?: self::INTERVAL_DEFAULT);
        $this->setData('recentAttempts',     $this->buildRecentAttemptsView($contextId));
        parent::initData();
    }

    /**
     * Read-only "recent activity" view for the Settings panel: decodes the
     * capped JSON event list written by MagicLoginHandler::recordAttempt(),
     * resolves user IDs to usernames for display, and translates event codes.
     * Purely for admin visibility — never used for any security decision.
     */
    private function buildRecentAttemptsView(int $contextId): array
    {
        $raw = (string) $this->plugin->getSetting($contextId, MagicLoginPlugin::RECENT_ATTEMPTS_SETTING);
        if ($raw === '') {
            return [];
        }
        $events = json_decode($raw, true);
        if (!is_array($events)) {
            return [];
        }

        $userCache = [];
        $view = [];
        foreach ($events as $event) {
            if (!is_array($event) || !isset($event['ts'], $event['event'])) {
                continue;
            }
            $userId   = isset($event['user_id']) ? (int) $event['user_id'] : null;
            $username = null;
            if ($userId) {
                if (!array_key_exists($userId, $userCache)) {
                    $user = Repo::user()->get($userId);
                    $userCache[$userId] = $user ? $user->getUsername() : null;
                }
                $username = $userCache[$userId];
            }
            $eventCode = (string) $event['event'];
            $view[] = [
                'time'  => date('Y-m-d H:i:s', (int) $event['ts']),
                'event' => __(self::EVENT_LABELS[$eventCode] ?? $eventCode),
                'user'  => $username ?? __('plugins.generic.magicLogin.activity.unknownUser'),
                'ip'    => (string) ($event['ip'] ?? ''),
            ];
        }
        return $view;
    }

    public function readInputData(): void
    {
        $this->readUserVars(['enabled', 'ttlMinutes', 'minIntervalSeconds']);
    }

    public function execute(...$functionArgs)
    {
        $contextId = Application::get()->getRequest()->getContext()->getId();

        $this->plugin->updateSetting($contextId, 'enabled', (bool) $this->getData('enabled'), 'bool');

        $ttl = (int) $this->getData('ttlMinutes');
        $ttl = max(self::TTL_MIN, min(self::TTL_MAX, $ttl ?: self::TTL_DEFAULT));
        $this->plugin->updateSetting($contextId, 'ttlMinutes', $ttl, 'int');

        $interval = (int) $this->getData('minIntervalSeconds');
        $interval = max(self::INTERVAL_MIN, min(self::INTERVAL_MAX, $interval ?: self::INTERVAL_DEFAULT));
        $this->plugin->updateSetting($contextId, 'minIntervalSeconds', $interval, 'int');

        return parent::execute(...$functionArgs);
    }
}
