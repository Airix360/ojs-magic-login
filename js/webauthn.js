/**
 * js/webauthn.js
 *
 * Client-side WebAuthn (passkey) ceremonies. No framework/build step — a
 * handful of DOM-ready listeners, matching this plugin's existing
 * vanilla-JS pages (request.tpl, totp.tpl).
 */
(function () {
  'use strict';

  function b64urlToBuffer(b64url) {
    var padded = b64url.replace(/-/g, '+').replace(/_/g, '/');
    while (padded.length % 4) { padded += '='; }
    var binary = atob(padded);
    var buffer = new Uint8Array(binary.length);
    for (var i = 0; i < binary.length; i++) { buffer[i] = binary.charCodeAt(i); }
    return buffer.buffer;
  }

  function bufferToB64url(buffer) {
    var bytes = new Uint8Array(buffer);
    var binary = '';
    for (var i = 0; i < bytes.byteLength; i++) { binary += String.fromCharCode(bytes[i]); }
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function getCsrfToken() {
    var meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.getAttribute('content') : '';
  }

  function postJson(url, body) {
    // PKPRequest::checkCSRF() reads the token from a request parameter
    // (getUserVar('csrfToken')), not a header — and PHP never populates
    // $_POST for a raw application/json body, so the token has to travel
    // as a query-string param (getUserVar() merges $_GET too) rather than
    // in the JSON body itself or a custom header.
    var sep = url.indexOf('?') === -1 ? '?' : '&';
    var urlWithToken = url + sep + 'csrfToken=' + encodeURIComponent(getCsrfToken());
    return fetch(urlWithToken, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
      body: JSON.stringify(body || {})
    }).then(function (res) { return res.json().then(function (data) { return { ok: res.ok, data: data }; }); });
  }

  function getJson(url) {
    return fetch(url, { credentials: 'same-origin' })
      .then(function (res) { return res.json().then(function (data) { return { ok: res.ok, data: data }; }); });
  }

  function setStatus(el, message, isError) {
    if (!el) { return; }
    el.textContent = message;
    el.style.display = message ? 'block' : 'none';
    el.className = isError ? 'magic-login-alert magic-login-alert-err' : 'magic-login-alert magic-login-alert-ok';
  }

  // ── Registration (Account Security page) ──────────────────────────────

  function initRegistration() {
    var btn = document.getElementById('webauthn-add-btn');
    if (!btn || typeof PublicKeyCredential === 'undefined') {
      if (btn) { btn.disabled = true; btn.title = 'Passkeys are not supported in this browser.'; }
      return;
    }
    var statusEl = document.getElementById('webauthn-status');
    var nicknameInput = document.getElementById('webauthn-nickname');

    btn.addEventListener('click', function () {
      btn.disabled = true;
      setStatus(statusEl, '', false);

      getJson(btn.dataset.optionsUrl).then(function (res) {
        if (!res.ok) { throw new Error((res.data && res.data.error) || 'Could not start passkey setup.'); }
        var options = res.data;
        var publicKey = {
          challenge: b64urlToBuffer(options.challenge),
          rp: options.rp,
          user: {
            id: b64urlToBuffer(options.user.id),
            name: options.user.name,
            displayName: options.user.displayName
          },
          pubKeyCredParams: options.pubKeyCredParams,
          timeout: options.timeout,
          attestation: options.attestation,
          authenticatorSelection: options.authenticatorSelection,
          excludeCredentials: (options.excludeCredentials || []).map(function (c) {
            return { type: c.type, id: b64urlToBuffer(c.id) };
          })
        };
        return navigator.credentials.create({ publicKey: publicKey });
      }).then(function (credential) {
        var attestationResponse = credential.response;
        var payload = {
          id: credential.id,
          response: {
            clientDataJSON: bufferToB64url(attestationResponse.clientDataJSON),
            attestationObject: bufferToB64url(attestationResponse.attestationObject),
            transports: (typeof attestationResponse.getTransports === 'function') ? attestationResponse.getTransports() : []
          }
        };
        var url = btn.dataset.verifyUrl + '?nickname=' + encodeURIComponent((nicknameInput && nicknameInput.value) || '');
        return postJson(url, payload);
      }).then(function (res) {
        if (!res.ok || !res.data.ok) { throw new Error((res.data && res.data.error) || 'Could not save the passkey.'); }
        window.location.reload();
      }).catch(function (err) {
        setStatus(statusEl, err && err.message ? err.message : String(err), true);
        btn.disabled = false;
      });
    });
  }

  // ── Sign-in (webauthnLogin.tpl) ────────────────────────────────────────

  function initLogin() {
    var form = document.getElementById('webauthnLoginForm');
    if (!form) { return; }
    if (typeof PublicKeyCredential === 'undefined') {
      setStatus(document.getElementById('webauthn-login-status'), 'Passkeys are not supported in this browser.', true);
      form.querySelector('button[type="submit"]').disabled = true;
      return;
    }
    var statusEl = document.getElementById('webauthn-login-status');
    var identifierInput = document.getElementById('webauthn-identifier');

    form.addEventListener('submit', function (event) {
      event.preventDefault();
      setStatus(statusEl, '', false);
      var submitBtn = form.querySelector('button[type="submit"]');
      submitBtn.disabled = true;

      postJson(form.dataset.optionsUrl, { identifier: identifierInput.value }).then(function (res) {
        if (!res.ok) { throw new Error((res.data && res.data.error) || 'Could not start sign-in.'); }
        var options = res.data;
        var publicKey = {
          challenge: b64urlToBuffer(options.challenge),
          rpId: options.rpId,
          timeout: options.timeout,
          userVerification: options.userVerification,
          allowCredentials: (options.allowCredentials || []).map(function (c) {
            return { type: c.type, id: b64urlToBuffer(c.id), transports: c.transports };
          })
        };
        return navigator.credentials.get({ publicKey: publicKey });
      }).then(function (credential) {
        var assertionResponse = credential.response;
        var payload = {
          id: credential.id,
          response: {
            clientDataJSON: bufferToB64url(assertionResponse.clientDataJSON),
            authenticatorData: bufferToB64url(assertionResponse.authenticatorData),
            signature: bufferToB64url(assertionResponse.signature)
          }
        };
        return postJson(form.dataset.verifyUrl, payload);
      }).then(function (res) {
        if (!res.ok || !res.data.ok) { throw new Error((res.data && res.data.error) || 'Sign-in failed. Try again or use another method.'); }
        window.location.href = res.data.redirect || '/';
      }).catch(function (err) {
        setStatus(statusEl, err && err.message ? err.message : String(err), true);
        submitBtn.disabled = false;
      });
    });
  }

  document.addEventListener('DOMContentLoaded', function () {
    initRegistration();
    initLogin();
  });
})();
