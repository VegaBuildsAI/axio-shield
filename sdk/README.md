# AXIO Shield SDK

Sensor web embebido. Se instala en el `<head>` del portal del cliente con dos `<script>`:

```html
<script src="/sdk/rules.js"></script>
<script src="/sdk/axio-shield.js" data-endpoint="https://shield.tu-dominio.com/ingest"></script>
```

- `data-endpoint` (o `window.AXIO_SHIELD_ENDPOINT`) define a dónde enviar los eventos.
  Por defecto `/ingest` (mismo origen que el backend).

## Qué envía (y qué NO)

Envía **solo metadata**: user-agent, timing, features estadísticas (longitud, entropía,
ratio de caracteres especiales) y *labels* de reglas que matchearon localmente
(ej. `prompt_injection.instruction_override`).

**Nunca** envía el contenido de los inputs, ni los campos `type="password"`. El escaneo
de patrones ocurre en el navegador; solo la conclusión (el label) viaja al backend.

## Qué sensa

- `page_load` — fingerprint inicial (flags de automatización: webdriver, headless, etc.)
- `form_submit` — labels + features + tiempo de llenado del formulario
- `xhr`/`fetch` — inspecciona el cuerpo localmente; solo reporta si hay labels

## Fail-safe

Si el backend no responde, el SDK no rompe nada: cae a modo pasivo (no bloquea, no lanza
errores visibles al usuario).

## Aislamiento de agentes existentes

El sensor usa una referencia al `fetch` original y deja pasar intactos los argumentos,
headers, body, respuesta y errores de cada request. No inspecciona ni genera telemetría para
rutas existentes de agentes o control: `/api/*`, `/mcp/*`, `/.well-known/*`, `/a2a*`,
`/agent-gateway*` y `/shield/*`. Solo acepta un endpoint de telemetría mismo-origen y
reporta rutas sin query string ni fragmento. Si el endpoint es externo o inválido, el SDK
se desactiva silenciosamente.

## Vocabulario de reglas

Los labels de `rules.js` coinciden con `backend/app/detection/rules.py`. Cambiar uno
implica actualizar el otro para mantener cliente y servidor en el mismo idioma.

## Build (opcional)

`rules.js` + `axio-shield.js` son JS vanilla, sin dependencias ni paso de build. Para
producción se pueden minificar/concatenar a `dist/axio-shield.min.js` (no incluido).
