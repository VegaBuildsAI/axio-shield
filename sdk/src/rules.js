/*
 * AXIO Shield SDK — Reglas deterministas del lado del cliente.
 *
 * PRIVACIDAD: estas reglas inspeccionan el contenido LOCALMENTE en el navegador y
 * devuelven SOLO etiquetas (labels) + features estadísticas. El texto crudo del usuario
 * NUNCA sale del navegador. El vocabulario de labels coincide con backend/app/detection/rules.py.
 */
(function (global) {
  "use strict";

  var PATTERNS = [
    ["prompt_injection.instruction_override", [
      /ignore\s+(all\s+)?(previous|prior|above)/i,
      /disregard\s+(the\s+)?(above|previous|prior)/i,
      /forget\s+(everything|all\s+previous)/i,
      /new\s+instructions?\s*[:\-]/i
    ]],
    ["prompt_injection.role_hijack", [
      /you\s+are\s+now/i,
      /system\s+prompt/i,
      /\bact\s+as\s+(an?|the)\b/i,
      /pretend\s+to\s+be/i
    ]],
    ["prompt_injection.exfil", [
      /(reveal|print|show|repeat|dump)[^.]{0,25}(system|prompt|instructions?|api[_\s-]?key|password|secret|token|env)/i,
      /environment\s+variables?/i
    ]],
    ["xss.script", [
      /<script\b/i,
      /on(error|load|click)\s*=/i,
      /javascript:/i
    ]],
    ["sqli", [
      /'\s*or\s*'?1'?\s*=\s*'?1/i,
      /union\s+select/i,
      /;\s*drop\s+table/i,
      /--\s/
    ]],
    ["ssrf", [
      /169\.254\.169\.254/,
      /file:\/\//i,
      /https?:\/\/(localhost|127\.0\.0\.1)/i,
      /metadata\.(google|internal)/i
    ]],
    ["swarm.deaddrop", [
      /remote\s+confirmed/i,
      /exposing?\s+creds?/i,
      /join\s+the\s+swarm/i,
      /\brecruit(ing)?\b/i,
      /^[A-Za-z0-9+/=]{48,}$/           // blob base64 largo en un campo libre
    ]]
  ];

  function scan(text) {
    if (!text || typeof text !== "string") return [];
    var hits = [];
    for (var i = 0; i < PATTERNS.length; i++) {
      var label = PATTERNS[i][0];
      var regexes = PATTERNS[i][1];
      for (var j = 0; j < regexes.length; j++) {
        if (regexes[j].test(text)) { hits.push(label); break; }
      }
    }
    return hits;
  }

  function shannonEntropy(s) {
    if (!s) return 0;
    var map = {}, len = s.length, i;
    for (i = 0; i < len; i++) { map[s[i]] = (map[s[i]] || 0) + 1; }
    var ent = 0;
    for (var k in map) {
      if (map.hasOwnProperty(k)) {
        var p = map[k] / len;
        ent -= p * (Math.log(p) / Math.log(2));
      }
    }
    return Math.round(ent * 100) / 100;
  }

  function features(values) {
    // values: array de strings (valores de campos). Devuelve SOLO estadísticas.
    var joined = values.join(" ");
    var maxLen = 0, special = 0, total = 0;
    for (var i = 0; i < values.length; i++) {
      if (values[i].length > maxLen) maxLen = values[i].length;
    }
    for (var j = 0; j < joined.length; j++) {
      total++;
      if (/[^A-Za-z0-9\s]/.test(joined[j])) special++;
    }
    var longBlob = false;
    for (var k = 0; k < values.length; k++) {
      if (/^[A-Za-z0-9+/=]{48,}$/.test(values[k].trim())) longBlob = true;
    }
    return {
      field_count: values.length,
      max_field_len: maxLen,
      special_char_ratio: total ? Math.round((special / total) * 1000) / 1000 : 0,
      entropy: shannonEntropy(joined),
      deaddrop_suspect: longBlob
    };
  }

  global.AxioShieldRules = { scan: scan, features: features };
})(typeof window !== "undefined" ? window : this);
