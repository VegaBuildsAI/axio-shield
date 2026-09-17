/*
 * AXIO Shield SDK — Sensor web embebido.
 *
 * Se embebe en el <head> del portal del cliente:
 *   <script src="/sdk/rules.js"></script>
 *   <script src="/sdk/axio-shield.js" data-endpoint="/ingest"></script>
 *
 * Qué hace:
 *   - Asigna un session_id estable (sessionStorage).
 *   - Sensa page_load, submits de formularios y llamadas fetch/XHR.
 *   - Corre reglas deterministas sobre el contenido LOCALMENTE (no lo envía).
 *   - Hace fingerprint de AI browsers / automatización.
 *   - Envía SOLO metadata (labels + features + user-agent + timing) al backend.
 *
 * FAIL-SAFE: si el backend no responde, el SDK cae a modo pasivo (no bloquea nada).
 */
(function () {
  "use strict";

  var script = document.currentScript || {};
  var ENDPOINT =
    (window.AXIO_SHIELD_ENDPOINT) ||
    (script.getAttribute && script.getAttribute("data-endpoint")) ||
    "/ingest";

  // Isolation boundary: the sensor is same-origin and pass-through only.
  // Existing site agents and infrastructure routes are never inspected.
  var PROTECTED_PREFIXES = [
    "/api/",
    "/mcp/",
    "/.well-known/",
    "/a2a",
    "/agent-gateway",
    "/shield/"
  ];
  var ORIGINAL_FETCH = window.fetch;

  function resolveUrl(value) {
    try {
      if (value && value.url) value = value.url;
      return new URL(String(value), window.location.href);
    } catch (e) {
      return null;
    }
  }

  function isSameOrigin(url) {
    return !!url && url.origin === window.location.origin;
  }

  function isProtectedPath(pathname) {
    for (var i = 0; i < PROTECTED_PREFIXES.length; i++) {
      var prefix = PROTECTED_PREFIXES[i];
      if (pathname === prefix.slice(0, -1) || pathname.indexOf(prefix) === 0) return true;
    }
    return false;
  }

  var endpointUrl = resolveUrl(ENDPOINT);
  var TELEMETRY_ENDPOINT = isSameOrigin(endpointUrl) && !isProtectedPath(endpointUrl.pathname)
    ? endpointUrl.href
    : "";

  function sessionId() {
    try {
      var sid = sessionStorage.getItem("axio_sid");
      if (!sid) {
        sid = "s_" + Math.random().toString(36).slice(2) + Date.now().toString(36);
        sessionStorage.setItem("axio_sid", sid);
      }
      return sid;
    } catch (e) {
      return "s_ephemeral_" + Math.random().toString(36).slice(2);
    }
  }

  var SID = sessionId();
  var formFirstTouch = {};

  function automationFingerprint() {
    var flags = [];
    try {
      if (navigator.webdriver) flags.push("webdriver");
      if (!navigator.languages || navigator.languages.length === 0) flags.push("no_languages");
      if (navigator.plugins && navigator.plugins.length === 0) flags.push("no_plugins");
      if (window.__nightmare || window._phantom || window.callPhantom) flags.push("headless_hook");
    } catch (e) { /* ignore */ }
    return flags;
  }

  function send(kind, matches, features, extra) {
    if (!TELEMETRY_ENDPOINT || !ORIGINAL_FETCH) return;
    var payload = {
      session_id: SID,
      kind: kind,
      path: location.pathname,
      ua: navigator.userAgent || "",
      features: features || {},
      client_matches: matches || [],
      client_score: 0.0,
      extra: extra || {}
    };
    try {
      // Use the original fetch reference so telemetry cannot re-enter the wrapper.
      ORIGINAL_FETCH.call(window, TELEMETRY_ENDPOINT, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
        keepalive: true
      }).catch(function () { /* fail-safe: modo pasivo */ });
    } catch (e) { /* fail-safe */ }
  }

  function scanValues(values) {
    var R = window.AxioShieldRules;
    var matches = [];
    if (R) {
      for (var i = 0; i < values.length; i++) {
        var hits = R.scan(values[i]);
        for (var j = 0; j < hits.length; j++) {
          if (matches.indexOf(hits[j]) === -1) matches.push(hits[j]);
        }
      }
    }
    var feats = R ? R.features(values) : {};
    return { matches: matches, features: feats };
  }

  // --- page_load: fingerprint inicial ---
  function onLoad() {
    var af = automationFingerprint();
    send("page_load", [], {}, { automation_flags: af });
  }

  // --- timing: marca el primer toque de cada formulario ---
  document.addEventListener("focusin", function (ev) {
    var form = ev.target && ev.target.form;
    if (form) {
      var id = form.getAttribute("data-axio-id") || form.name || "form";
      if (!formFirstTouch[id]) formFirstTouch[id] = Date.now();
    }
  });

  // --- submit: escanea valores localmente, envía labels + features + fill_ms ---
  document.addEventListener("submit", function (ev) {
    var form = ev.target;
    if (!form || form.tagName !== "FORM") return;
    var values = [];
    var els = form.querySelectorAll("input, textarea, select");
    for (var i = 0; i < els.length; i++) {
      if (els[i].type === "password") continue; // nunca tocar passwords
      if (els[i].value) values.push(String(els[i].value));
    }
    var res = scanValues(values);
    var id = form.getAttribute("data-axio-id") || form.name || "form";
    if (formFirstTouch[id]) {
      res.features.form_fill_ms = Date.now() - formFirstTouch[id];
      formFirstTouch[id] = 0;
    }
    send("form_submit", res.matches, res.features, {});
  }, true);

  // --- fetch: inspecciona el cuerpo localmente (solo labels salen) ---
  if (ORIGINAL_FETCH) {
    window.fetch = function (input, init) {
      try {
        var requestUrl = resolveUrl(input);
        // Never inspect, alter, or emit telemetry for existing agents,
        // control-plane routes, or cross-origin requests.
        if (!requestUrl || !isSameOrigin(requestUrl) || isProtectedPath(requestUrl.pathname)) {
          return ORIGINAL_FETCH.apply(this, arguments);
        }
        if (init && init.body && typeof init.body === "string") {
          var res = scanValues([init.body]);
          if (res.matches.length) send("xhr", res.matches, res.features, { route: requestUrl.pathname });
        }
      } catch (e) { /* ignore */ }
      // Strict pass-through: preserve the original arguments and return value.
      return ORIGINAL_FETCH.apply(this, arguments);
    };
  }

  if (document.readyState === "complete" || document.readyState === "interactive") {
    onLoad();
  } else {
    window.addEventListener("DOMContentLoaded", onLoad);
  }

  window.AxioShield = { sessionId: SID, endpoint: ENDPOINT, version: "0.1.0" };
})();
