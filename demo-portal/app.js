/* Lógica del portal-banco demo. El SDK AXIO Shield ya está enganchado a los submits;
   aquí solo manejamos la UI (login ficticio, confirmación de transferencia). */
(function () {
  "use strict";
  var loginView = document.getElementById("login-view");
  var appView = document.getElementById("app-view");
  var result = document.getElementById("result");

  document.getElementById("login-form").addEventListener("submit", function (ev) {
    ev.preventDefault();
    loginView.hidden = true;
    appView.hidden = false;
  });

  document.getElementById("transfer-form").addEventListener("submit", function (ev) {
    ev.preventDefault();
    var f = ev.target;
    result.hidden = false;
    result.textContent =
      "✓ Transferencia registrada a " + (f.destino.value || "destino") +
      " por ₡" + (f.monto.value || "0") + ". (demo)";
    f.reset();
  });

  document.getElementById("logout").addEventListener("click", function () {
    appView.hidden = true;
    loginView.hidden = false;
  });
})();
