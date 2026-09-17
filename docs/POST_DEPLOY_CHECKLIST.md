# AXIO Shield — Checklist de verificación post-deploy (producción)

> Sitio: `www.axiostaging.com` · Worker: `axio-shield-gateway` (`/shield/*`, observe mode)
> SDK sensor: `react-scaffold/public/shield-sdk/` embebido en `index.html`.
> Última verificación: 2026-09-17 (deploy del sensor) — todos los checks ✅.

## A. Worker de defensa (backend)

```bash
# 1) Salud + modo (debe: mode observe, enforcement_enabled false)
curl -s https://www.axiostaging.com/shield/health
#   -> {"status":"ok","mode":"observe","engine":"deterministic","enforcement_enabled":false}

# 2) Integridad del audit log (debe: valid true)
curl -s https://www.axiostaging.com/shield/api/audit/verify
#   -> {"valid":true,"broken_at_seq":null}

# 3) Defensores-only: NINGÚN endpoint de ataque expuesto (debe: 404)
curl -s -o /dev/null -w "%{http_code}\n" -XPOST https://www.axiostaging.com/shield/api/arena/launch -d '{}'
#   -> 404
```

## B. SDK sensor en el sitio (mismo-origen, AEO-safe)

```bash
# 4) El HTML de producción incluye los 2 <script defer> del sensor
curl -s https://www.axiostaging.com/ | grep -c "shield-sdk"      # -> 2

# 5) Los archivos del SDK se sirven mismo-origen (debe: 200, application/javascript)
curl -s -o /dev/null -w "%{http_code}\n" https://www.axiostaging.com/shield-sdk/rules.js
curl -s -o /dev/null -w "%{http_code}\n" https://www.axiostaging.com/shield-sdk/axio-shield.js
```

## C. Prueba en navegador (que el sensor DISPARE de verdad)

1. Abrir `https://www.axiostaging.com/` en el navegador (DevTools abierto).
2. **Console** → no debe haber errores de CSP de `shield-sdk` ni de `/shield/ingest`.
   - (Es esperado y ajeno a Shield el error del beacon `static.cloudflareinsights.com`,
     que el CSP del sitio ya bloqueaba desde antes.)
3. **Network** → filtrar `shield`:
   - `GET /shield-sdk/rules.js` y `/shield-sdk/axio-shield.js` → 200.
   - `POST /shield/ingest` (page_load) → 200. *(si no aparece al instante, recargar)*
4. En **Console**, prueba directa del pipeline:
   ```js
   await fetch('/shield/ingest',{method:'POST',headers:{'Content-Type':'application/json'},
     body:JSON.stringify({session_id:'probe',kind:'page_load',ua:navigator.userAgent})}).then(r=>r.json())
   // -> {ok:true, score:0, matched_rules:[], trust:"client_hint"}   (page load benigno)
   ```

## D. Que esté "viendo" tráfico real

```bash
# 6) Con visitas reales, la lista de incidentes crece (detecciones reales; los benignos NO
#    generan incidente — solo lo hacen las señales de ataque, p.ej. AI-browsers/bots).
curl -s https://www.axiostaging.com/shield/api/incidents | node -e 'const d=JSON.parse(require("fs").readFileSync(0));console.log("incidentes:",d.length)'

# 7) Matriz de cobertura (técnicas detectadas en vivo)
curl -s https://www.axiostaging.com/shield/api/coverage | node -e 'const d=JSON.parse(require("fs").readFileSync(0));console.log(JSON.stringify(d.summary))'
```
> Nota: el sitio atrae crawlers de IA (GPTBot, PerplexityBot, etc.) por el AEO; esos disparan
> `ai_browser.ua` y aparecerán como incidentes reales — buena señal de que el sensor "ve".

## E. AEO / sitio intactos (no romper)

```bash
curl -s -o /dev/null -w "robots  %{http_code}\n"  https://www.axiostaging.com/robots.txt   # 200
curl -s -o /dev/null -w "sitemap %{http_code}\n"  https://www.axiostaging.com/sitemap.xml  # 200
curl -s -o /dev/null -w "llms    %{http_code}\n"  https://www.axiostaging.com/llms.txt     # 200
curl -s https://www.axiostaging.com/ | grep -c "application/ld+json"                        # 1 (schema intacto)
```
- Correr **Lighthouse** una vez y comparar Core Web Vitals con el baseline (el SDK es `defer`
  y ~10 KB; no debe mover métricas de forma perceptible).

## F. Entrenamiento / validación (NUNCA desde el sitio)

- El simulador de atacantes (`simulator/`) es **solo para entrenar/validar** offline: se corre a
  mano contra `wrangler dev` o un preview, ajustando el allowlist del `ScopeGuard`. El sitio
  jamás ejecuta ataques.
- Validación en vivo real = **pentest + GRC red-team** contra los defensores desplegados.

## G. Rollback (si algo se ve mal)

- **SDK del sitio:** quitar los 2 `<script defer src="/shield-sdk/...">` de
  `react-scaffold/index.html`, `npm run deploy`. Desinstrumenta sin tocar nada más.
- **Worker:** `wrangler deployments list` + `wrangler rollback` (en `cloudflare/shield-worker/`).

## H. Pendiente opcional

- **Modo Claude** (juicio en casos ambiguos): `wrangler secret put ANTHROPIC_API_KEY` en el
  Worker. Hoy corre determinista (seguro y predecible para observe).
- Cuando se decida **enforcement**: activarlo con human-gate (aprobación por incidente), nunca
  bloqueo automático en el primer tramo.
