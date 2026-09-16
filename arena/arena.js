/* War Room: dispara ataques y muestra atacantes + defensores en vivo por WebSocket. */
(function () {
  "use strict";

  var WS_URL = (location.protocol === "https:" ? "wss://" : "ws://") + location.host + "/ws";
  var conn = document.getElementById("conn");
  var feed = document.getElementById("feed");

  var ICONS = {
    AttackDirector: "🎯", BASELINE_USER: "👤", INJECTION_AGENT: "💉", BROWSER_AGENT: "🤖",
    EXFILTRATION_AGENT: "📤", SWARM_COORDINATOR: "🕸️", A2A_IMPERSONATOR: "🎭", HUMAN_OPERATOR: "🧑‍💻",
    TOOL_POISONING_AGENT: "🧰", MEMORY_POISONING_AGENT: "🧠", IDENTITY_ABUSE_AGENT: "🪪",
    CHAIN_AGENT: "⛓️", ADAPTIVE_AGENT: "🦎", SDK_BYPASS: "🚪",
    RECON_AGENT: "🔍", CREDENTIAL_AGENT: "🗝️", LATERAL_AGENT: "↔️", PRIVESC_AGENT: "⬆️",
    PERSISTENCE_AGENT: "📌", ATTACKER: "☠️",
    SENTINEL: "🛰️", ORACLE: "🔮", TRACKER: "🧭", WARDEN: "🛡️", SPECTER: "👁️",
    HERALD: "📣", LOCKDOWN: "🔒", SCRIBE: "📜",
  };
  var DEF_ACTION = {
    scored: "evaluó evento", classified: "clasificó amenaza", swarm_detected: "detectó swarm",
    killchain_detected: "detectó kill-chain", attack_path_detected: "mapeó ruta de ataque",
    integrity_verdict: "verificó integridad", identity_verdict: "verificó identidad",
    alert: "alertó al SOC", human_gate_action: "aplicó contención",
  };

  var counts = { att: 0, det: 0, con: 0, swarm: 0 };
  var seenIncidents = {};

  // ---------- Roster ----------
  function agentCard(a, side) {
    var el = document.createElement("div");
    el.className = "agent";
    el.id = "ag_" + a.id;
    el.innerHTML = '<div class="ico">' + (ICONS[a.id] || (side === "att" ? "☠️" : "🛡️")) + "</div>" +
      '<div class="body"><div class="nm">' + a.label + "</div>" +
      '<div class="ds">' + a.desc + '</div><div class="act" id="act_' + a.id + '"></div></div>';
    return el;
  }

  fetch("/api/arena/roster").then(function (r) { return r.json(); }).then(function (roster) {
    var att = document.getElementById("attackers"), def = document.getElementById("defenders");
    roster.attackers.forEach(function (a) { att.appendChild(agentCard(a, "att")); });
    roster.defenders.forEach(function (a) { def.appendChild(agentCard(a, "def")); });
  });
  fetch("/health").then(function (r) { return r.json(); }).then(function (h) {
    document.getElementById("s-mode").textContent = h.stub_mode ? "STUB" : "Claude";
  }).catch(function () {});

  function pulse(agentId, action) {
    var card = document.getElementById("ag_" + agentId);
    if (!card) return;
    card.classList.add("active");
    var act = document.getElementById("act_" + agentId);
    if (act && action) act.textContent = action;
    clearTimeout(card._t);
    card._t = setTimeout(function () { card.classList.remove("active"); }, 1400);
  }

  function fmt(ts) { return new Date((ts || Date.now() / 1000) * 1000).toLocaleTimeString("es-CR"); }

  function addRow(kind, who, text, ts, badge) {
    var row = document.createElement("div");
    row.className = "row " + kind;
    var b = badge ? ' <span class="badge ' + badge + '">' + badge + "</span>" : "";
    row.innerHTML = '<span class="t">' + fmt(ts) + '</span><span class="who">' + who + b +
      '</span><span class="what">' + text + "</span>";
    feed.insertBefore(row, feed.firstChild);
    while (feed.childNodes.length > 120) feed.removeChild(feed.lastChild);
  }

  function setCounts() {
    document.getElementById("s-att").textContent = counts.att;
    document.getElementById("s-det").textContent = counts.det;
    document.getElementById("s-con").textContent = counts.con;
    document.getElementById("s-swarm").textContent = counts.swarm;
  }

  // ---------- WebSocket ----------
  function connect() {
    var ws = new WebSocket(WS_URL);
    ws.onopen = function () { conn.textContent = "conectado"; conn.className = "ok";
      setInterval(function () { if (ws.readyState === 1) ws.send("ping"); }, 20000); };
    ws.onclose = function () { conn.textContent = "desconectado"; conn.className = "down"; setTimeout(connect, 2000); };
    ws.onmessage = function (ev) {
      var m = JSON.parse(ev.data);
      if (m.type === "attack") {
        counts.att++; setCounts();
        pulse(m.attacker_id, (m.phase || "") + " · " + (m.technique || ""));
        addRow("attack", m.attacker_id, (m.phase || "") + " → " + (m.technique || ""), m.ts, m.source);
      } else if (m.type === "defense") {
        pulse(m.agent, DEF_ACTION[m.action] || m.action);
        if (m.action === "swarm_detected") { counts.swarm++; setCounts(); }
        if (m.action === "human_gate_action") { counts.con++; setCounts(); }
        if (m.action !== "scored") addRow("defense", m.agent, DEF_ACTION[m.action] || m.action, m.ts);
      } else if (m.type === "incident") {
        var inc = m.incident;
        if (!seenIncidents[inc.id]) { seenIncidents[inc.id] = 1; counts.det++; setCounts(); }
        var att = (inc.frameworks && inc.frameworks.attack && inc.frameworks.attack.length)
          ? " · ATT&CK " + inc.frameworks.attack.map(function (a) { return a.split(" ")[0]; }).join(",")
          : "";
        addRow("incident", "INCIDENTE", inc.owasp + " · " + inc.owasp_name + " · " + inc.urgency +
          " (" + inc.attacker_profile + ")" + att, inc.ts);
      } else if (m.type === "snapshot") {
        (m.incidents || []).forEach(function (inc) {
          if (!seenIncidents[inc.id]) { seenIncidents[inc.id] = 1; counts.det++; }
          if (inc.swarm && inc.swarm.coordinated) counts.swarm++;
          if (inc.status === "contained") counts.con++;
        });
        setCounts();
      } else if (m.type === "update") {
        if (m.incident && m.incident.status === "contained") { counts.con++; setCounts(); }
      }
    };
  }

  // ---------- Disparar ataques (yo, el atacante) ----------
  function launch(scenario, extra) {
    var body = Object.assign({ scenario: scenario }, extra || {});
    fetch("/api/arena/launch", {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
    });
  }

  document.querySelectorAll(".btns button[data-scn]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var scn = btn.getAttribute("data-scn");
      var sessions = parseInt(document.getElementById("sessions").value, 10) || 4;
      launch(scn, scn === "swarm" ? { sessions: sessions } : {});
    });
  });

  document.getElementById("launch-manual").addEventListener("click", function () {
    var text = document.getElementById("payload").value;
    // El payload se escanea LOCALMENTE; al backend solo van los labels, nunca el texto.
    var labels = (window.AxioShieldRules ? window.AxioShieldRules.scan(text) : []);
    if (!labels.length) labels = ["prompt_injection.instruction_override"];
    launch("manual", { payload_labels: labels });
    document.getElementById("payload").value = "";
  });

  connect();
})();
