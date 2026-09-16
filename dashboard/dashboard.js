/* SOC dashboard: WebSocket en vivo + acciones human-gate + grafo de swarm. */
(function () {
  "use strict";

  var API = "";                       // mismo origen que el backend
  var WS_URL = (location.protocol === "https:" ? "wss://" : "ws://") + location.host + "/ws";
  var incidents = {};                 // id -> incident
  var order = [];                     // ids en orden de llegada (para feed)

  var feed = document.getElementById("feed");
  var conn = document.getElementById("conn");

  // ---------- WebSocket ----------
  function connect() {
    var ws = new WebSocket(WS_URL);
    ws.onopen = function () { conn.textContent = "conectado"; conn.className = "ok";
      setInterval(function () { if (ws.readyState === 1) ws.send("ping"); }, 20000); };
    ws.onclose = function () { conn.textContent = "desconectado"; conn.className = "down";
      setTimeout(connect, 2000); };
    ws.onmessage = function (ev) {
      var msg = JSON.parse(ev.data);
      if (msg.type === "snapshot") { (msg.incidents || []).forEach(upsert); }
      else if (msg.type === "incident" || msg.type === "update") { upsert(msg.incident); }
      render();
    };
  }

  function upsert(inc) {
    if (!inc) return;
    if (!incidents[inc.id]) order.unshift(inc.id);
    incidents[inc.id] = inc;
  }

  // ---------- Acciones (human-gate) ----------
  function act(id, action) {
    fetch(API + "/api/incidents/" + id + "/action", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ action: action, operator: "analyst-soc" })
    }).then(function (r) { return r.json(); })
      .then(function (res) { if (res.ok) { upsert(res.incident); render(); } });
  }
  window._axioAct = act;

  // ---------- Render ----------
  function fmtTime(ts) { return new Date(ts * 1000).toLocaleTimeString("es-CR"); }

  function render() {
    var total = order.length, contained = 0, swarms = 0, mode = "—";
    var html = "";
    if (!total) feed.innerHTML = '<div class="empty">Esperando eventos del portal…</div>';

    for (var i = 0; i < order.length; i++) {
      var inc = incidents[order[i]];
      if (inc.status === "contained") contained++;
      if (inc.swarm && inc.swarm.coordinated) swarms++;

      var chips = (inc.matched_rules || []).map(function (r) {
        return '<span class="chip">' + r + "</span>";
      }).join("");

      var swarmHtml = "";
      if (inc.swarm && inc.swarm.coordinated) {
        var roles = Object.keys(inc.swarm.roles || {}).map(function (s) {
          return s.slice(0, 8) + "…: <b>" + inc.swarm.roles[s] + "</b>";
        }).join(" · ");
        swarmHtml = '<div class="swarm">⚠ <b>SWARM COORDINADO</b> — ' +
          (inc.swarm.session_ids || []).length + " sesiones · " +
          (inc.swarm.c2_indicator || "") + "<br />" + roles + "</div>";
      }

      var actions = "";
      if (inc.status === "open") {
        actions = '<div class="actions">' +
          '<button onclick="_axioAct(\'' + inc.id + "','rate_limit')\">Rate-limit</button>" +
          '<button onclick="_axioAct(\'' + inc.id + "','block_session')\">Bloquear sesión</button>" +
          '<button onclick="_axioAct(\'' + inc.id + "','revoke_token')\">Revocar token</button>" +
          '<button onclick="_axioAct(\'' + inc.id + "','dismiss')\">Descartar</button></div>";
      } else {
        actions = '<div class="actions"><span class="status ' + inc.status + '">' +
          inc.status.toUpperCase() + "</span></div>";
      }

      html += '<div class="card ' + inc.urgency + '">' +
        '<div class="row"><span class="owasp">' + inc.owasp + " · " + inc.owasp_name + "</span>" +
        '<span class="badge ' + inc.urgency + '">' + inc.urgency + "</span></div>" +
        '<div class="meta">' + fmtTime(inc.ts) + " · perfil <b>" + inc.attacker_profile +
        "</b> · sesión " + inc.session_id.slice(0, 12) + "… · score " + inc.score + "</div>" +
        '<div class="chips">' + chips + "</div>" +
        swarmHtml +
        '<div class="rationale">' + (inc.rationale || "") + "</div>" +
        actions + "</div>";
    }
    if (total) feed.innerHTML = html;

    document.getElementById("s-total").textContent = total;
    document.getElementById("s-contain").textContent = contained;
    document.getElementById("s-swarm").textContent = swarms;

    drawGraph();
  }

  // ---------- Grafo de swarm (SVG radial) ----------
  function drawGraph() {
    var svg = document.getElementById("graph");
    var info = document.getElementById("graph-info");
    // último incidente con swarm coordinado
    var swarmInc = null;
    for (var i = 0; i < order.length; i++) {
      var inc = incidents[order[i]];
      if (inc.swarm && inc.swarm.coordinated) { swarmInc = inc; break; }
    }
    if (!swarmInc) { svg.innerHTML = ""; info.textContent = "Sin coordinación de swarm detectada."; return; }

    var sessions = swarmInc.swarm.session_ids || [];
    var roles = swarmInc.swarm.roles || {};
    var cx = 200, cy = 150, R = 100;
    var parts = [];
    // aristas al centro (C2)
    var center = { x: cx, y: cy };
    var pts = sessions.map(function (s, idx) {
      var a = (2 * Math.PI * idx) / Math.max(sessions.length, 1) - Math.PI / 2;
      return { s: s, x: cx + R * Math.cos(a), y: cy + R * Math.sin(a) };
    });
    pts.forEach(function (p) {
      parts.push('<line x1="' + center.x + '" y1="' + center.y + '" x2="' + p.x +
        '" y2="' + p.y + '" stroke="#6b2340" stroke-width="1.5" />');
    });
    pts.forEach(function (p) {
      var role = roles[p.s] || "member";
      var color = role === "C2_manager" ? "#fb7185" : role === "exfiltrator" ? "#f97316" :
        role === "exploiter" ? "#eab308" : "#38bdf8";
      parts.push('<circle cx="' + p.x + '" cy="' + p.y + '" r="16" fill="' + color + '" opacity="0.9" />');
      parts.push('<text x="' + p.x + '" y="' + (p.y + 30) + '" fill="#8195ad" font-size="9" ' +
        'text-anchor="middle">' + role + "</text>");
    });
    parts.push('<circle cx="' + cx + '" cy="' + cy + '" r="20" fill="#0b1220" stroke="#fb7185" stroke-width="2" />');
    parts.push('<text x="' + cx + '" y="' + (cy + 3) + '" fill="#fb7185" font-size="9" text-anchor="middle">SWARM</text>');
    svg.innerHTML = parts.join("");
    info.textContent = "Confianza " + swarmInc.swarm.confidence + " · " + (swarmInc.swarm.c2_indicator || "");
  }

  // ---------- Verificar audit log ----------
  document.getElementById("verify").addEventListener("click", function () {
    fetch(API + "/api/audit/verify").then(function (r) { return r.json(); })
      .then(function (res) {
        alert(res.valid
          ? "✓ Audit log íntegro — la cadena de hash es válida."
          : "✗ Cadena rota en seq " + res.broken_at_seq);
      });
  });

  // ---------- init ----------
  fetch(API + "/health").then(function (r) { return r.json(); }).then(function (h) {
    document.getElementById("s-mode").textContent = h.stub_mode ? "STUB" : "Claude";
  }).catch(function () {});
  connect();
})();
