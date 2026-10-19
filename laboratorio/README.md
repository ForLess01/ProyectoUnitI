# Laboratorio local con datos sintéticos

Este laboratorio propio implementa un servicio HTTP mínimo para comprobar controles de autenticación, MFA, autorización, auditoría, límites de solicitud, detección y recuperación. Las cuentas y archivos son fixtures ficticios. **No se accedió ni se atribuye ningún hallazgo a la Universidad Nacional del Altiplano ni a otra institución.**

## Runtime e identidad de imagen

El resultado ya capturado usó una imagen preexistente del entorno: `marfil-pdf-test:latest`, Python 3.12.3, config image ID `sha256:4180697e2ec643227d99f19ffd95f4315e496e5db5192b9ce328a96ce6214310`. **La imagen no se distribuye.** El helper verifica `docker image inspect --format '{{.Id}}' "$LAB_RUNTIME_IMAGE"` contra `LAB_RUNTIME_IMAGE_ID` y arranca con `--pull=never`; así no sustituye silenciosamente esa identidad ni descarga una imagen bajo el mismo nombre.

Para reproducir la identidad del entorno capturado, desde la raíz del proyecto:

```bash
LAB_RUNTIME_IMAGE=marfil-pdf-test:latest \
LAB_RUNTIME_IMAGE_ID=sha256:4180697e2ec643227d99f19ffd95f4315e496e5db5192b9ce328a96ce6214310 \
LAB_RUNTIME_IMAGE_SOURCE=preexisting-local-image \
python3 herramientas/lab_capture.py --start-container
```

### Alternativa pública más portable (no ejecutada en esta captura)

Consulté sólo metadatos del tag oficial con `docker manifest inspect --verbose`; no descargué capas. Para Docker Linux/ARM64, la referencia multi-arch inmutable es `docker.io/library/python:3.12.13-slim@sha256:229a2c5bfa27522db7815ea81f9bed70af17ccb9de9fc7ad142b1877b5830d36`; el manifiesto ARM64 es `sha256:adbc7c33e0abc183557d1d14ce5eb5d261aaadff5451c81a8db636b3ebefcdf6`, con config image ID `sha256:0445c02b019cf3f9d61bac90acaac8e2d37ae6991b3384bd9d75fec93bcdfe98`.

Si esa imagen no está disponible localmente y se autoriza la descarga de dependencias, el conjunto de capas reportado por el registro es de aproximadamente 43 MB para ARM64:

```bash
docker pull --platform linux/arm64 \
  docker.io/library/python:3.12.13-slim@sha256:229a2c5bfa27522db7815ea81f9bed70af17ccb9de9fc7ad142b1877b5830d36
LAB_RUNTIME_IMAGE=docker.io/library/python:3.12.13-slim@sha256:229a2c5bfa27522db7815ea81f9bed70af17ccb9de9fc7ad142b1877b5830d36 \
LAB_RUNTIME_IMAGE_ID=sha256:0445c02b019cf3f9d61bac90acaac8e2d37ae6991b3384bd9d75fec93bcdfe98 \
LAB_RUNTIME_IMAGE_SOURCE=official-python-3.12.13-slim-pinned \
python3 herramientas/lab_capture.py --start-container
```

El helper crea/verifica una red Docker `--internal`, comprueba localmente el image ID esperado, usa `--pull=never` durante la ejecución y aplica los mismos mounts de solo lectura, `tmpfs`, límites y entorno `env -i`. La aplicación y las pruebas Python usan sólo la biblioteca estándar; Playwright Core se reserva para automatizar Chrome y tomar capturas. La alternativa oficial es suficiente para el laboratorio, pero **cambia la imagen, su config ID y potencialmente versiones de SQLite/browser host**. No debe declararse como el runtime que produjo las capturas existentes ni se promete igualdad píxel a píxel. El manifiesto de código/fixtures identifica las condiciones fuente; cada nueva ejecución debe regenerar resultados y evidencia con el runtime realmente utilizado.

## Ejecución del servicio y capturas

El contenedor no publica puertos. El servicio escucha en su propio loopback (`127.0.0.1:8765`) dentro de una red interna. `herramientas/lab_capture.py --serve` ofrece dos relés locales explícitos: la UI del laboratorio en `127.0.0.1:18765` y la consola PTY en `127.0.0.1:18766`. El relé de la aplicación reenvía cada solicitud acotada mediante `docker exec` al loopback del contenedor; no abre rutas de salida externas.

La consola ejecuta sólo estos grupos fijos, cada uno dentro del contenedor:

| Grupo | Comando exacto ejecutado por PTY | Casos |
|---|---|---|
| Autenticación/MFA | `docker exec --interactive --tty --env TERM=dumb proyectouniti-lab-demo /usr/bin/env -i PATH=/usr/local/bin:/usr/bin:/bin PYTHONPATH=/app PYTHONDONTWRITEBYTECODE=1 TZ=UTC TERM=dumb LAB_OUTPUT_ROOT=/outputs python3 -m laboratorio.run_tests --group auth_mfa --artifact-dir /outputs --runtime-dir /outputs/runtime` | AUTH-01–03 |
| RBAC/IDOR | `docker exec --interactive --tty --env TERM=dumb proyectouniti-lab-demo /usr/bin/env -i PATH=/usr/local/bin:/usr/bin:/bin PYTHONPATH=/app PYTHONDONTWRITEBYTECODE=1 TZ=UTC TERM=dumb LAB_OUTPUT_ROOT=/outputs python3 -m laboratorio.run_tests --group rbac_idor --artifact-dir /outputs --runtime-dir /outputs/runtime` | RBAC-01–02, IDOR-01 |
| Integridad/auditoría | `docker exec --interactive --tty --env TERM=dumb proyectouniti-lab-demo /usr/bin/env -i PATH=/usr/local/bin:/usr/bin:/bin PYTHONPATH=/app PYTHONDONTWRITEBYTECODE=1 TZ=UTC TERM=dumb LAB_OUTPUT_ROOT=/outputs python3 -m laboratorio.run_tests --group integrity_audit --artifact-dir /outputs --runtime-dir /outputs/runtime` | INT-01, RBAC-03, AUDIT-01 |
| Tamaño/revocación | `docker exec --interactive --tty --env TERM=dumb proyectouniti-lab-demo /usr/bin/env -i PATH=/usr/local/bin:/usr/bin:/bin PYTHONPATH=/app PYTHONDONTWRITEBYTECODE=1 TZ=UTC TERM=dumb LAB_OUTPUT_ROOT=/outputs python3 -m laboratorio.run_tests --group size_revocation --artifact-dir /outputs --runtime-dir /outputs/runtime` | INPUT-01, SESSION-01 |
| ATT&CK/recuperación | `docker exec --interactive --tty --env TERM=dumb proyectouniti-lab-demo /usr/bin/env -i PATH=/usr/local/bin:/usr/bin:/bin PYTHONPATH=/app PYTHONDONTWRITEBYTECODE=1 TZ=UTC TERM=dumb LAB_OUTPUT_ROOT=/outputs python3 -m laboratorio.run_tests --group attack_backup --artifact-dir /outputs --runtime-dir /outputs/runtime` | ATTACK-01, RECOVERY-01 |

Para generar las cinco capturas de PTY y las cuatro del navegador, instala únicamente el paquete Playwright Core fijado en `browser-tools/package-lock.json` (el entorno de esta ejecución lo resolvió desde caché, sin descargar navegador):

```bash
npm ci --offline --no-audit --no-fund --prefix laboratorio/browser-tools
env -i PATH="$PATH" HOME="$HOME" DOCKER_CONTEXT=desktop-linux \
  node laboratorio/browser-tools/capture.js \
  --base-url http://127.0.0.1:18765 \
  --terminal-url http://127.0.0.1:18766 \
  --output-dir evidencias/laboratorio/capturas
```

El script abre Google Chrome en modo visible con un perfil Playwright temporal y dos contextos aislados. Las rutas de red de cada contexto sólo permiten su origen `127.0.0.1`; cualquier origen distinto se aborta. La consola PTY inicia el proceso real al pulsar el botón, muestra el comando allowlisted y su salida, y reporta el código de salida del proceso. No contiene transcripciones precargadas.

El script vuelve a ejecutar los cinco grupos PTY y cuatro flujos del navegador para regenerar como una sola unidad los resúmenes de 13+4 casos, los nueve PNG, índices, timestamps y hashes; los grupos terminales no se cuentan otra vez como casos funcionales.

Al finalizar la captura, guarda primero el log bruto de arranque para incluirlo en el manifiesto:

```bash
python3 herramientas/lab_capture.py --collect-server-log
```

Después agrega los resultados observados y genera el índice, el manifiesto de código/fixtures y el manifiesto de evidencia desde el contenedor:

```bash
docker exec proyectouniti-lab-demo /usr/bin/env -i \
  PATH=/usr/local/bin:/usr/bin:/bin PYTHONPATH=/app \
  PYTHONDONTWRITEBYTECODE=1 LAB_OUTPUT_ROOT=/outputs TZ=UTC \
  python3 -m laboratorio.finalize --evidence-dir /outputs
```

Detén el contenedor y elimina la red interna:

```bash
docker stop proyectouniti-lab-demo && docker network rm proyectouniti-lab-isolated
```

## Casos y contratos comprobados

| ID | Resultado esperado comprobado |
|---|---|
| AUTH-01/02/03 | Credencial incorrecta y contraseña sin MFA denegadas; TOTP RFC 6238 válido crea una sesión. Incluye comprobación del vector SHA-1 RFC 6238 sin imprimir el código. |
| RBAC-01/02/03 | Lector denegado en administración; admin permitido; editor modifica sólo su objeto asignado. |
| IDOR-01 | Lectura propia de A permitida; lectura de B responde 404 genérico y no revela contenido. |
| INT-01 | Modificación del lector responde 403 y una lectura posterior confirma que el contenido no cambió. |
| AUDIT-01 | El evento observado contiene actor, UTC, acción, resultado y el mismo `request_id`; no se guarda la contraseña. |
| INPUT-01 | Una solicitud de 65 537 bytes recibe 413 con límite de 65 536; la siguiente solicitud válida recibe 201. |
| SESSION-01 | Se reutiliza el valor de sesión anterior sólo dentro de la prueba; después de revocarlo, el servidor responde 401. El valor no se registra. |
| ATTACK-01 | T1083/T1005/T1074.001 sólo enumera, copia y prepara los dos archivos sintéticos incluidos; `LAB-DET-001` genera una alerta al observar el staging. |
| RECOVERY-01 | Se altera un byte en una copia de trabajo descartable, se constata la alteración y que origen/backup siguen intactos, luego se restaura desde el backup y se comprueba igualdad SHA-256 final. Incluye hashes before/damaged/restored y timings por fase. |

## Archivos de evidencia

| Ruta | Contenido |
|---|---|
| `evidencias/laboratorio/resultados.json` | Casos, esperado/observado, `pass`, comando, UTC, duración, stack, límites y KPIs medidos. |
| `evidencias/laboratorio/evidence_index.json` | ID, ruta, caso, caption factual y método en metadata para cada captura. |
| `evidencias/laboratorio/manifest.sha256` | Hash SHA-256 de todos los archivos regulares de evidencia, incluido el manifiesto fuente, salvo el propio manifiesto y `.keep`. |
| `evidencias/laboratorio/source_manifest.sha256` | Hash SHA-256 del código y fixtures bajo `laboratorio/`, el lockfile, y `herramientas/lab_capture.py`; rutas relativas a la raíz del proyecto. |
| `evidencias/laboratorio/groups/` | Resumen medido por grupo; comandos completos ejecutados desde PTY. |
| `evidencias/laboratorio/logs/` | Salida bruta de grupos, PTY, navegador y arranque del servidor. |
| `evidencias/laboratorio/runtime/startup.json` | Image reference, Docker config image ID validado, origen, digest, red y argv efectiva de `docker run`. |
| `evidencias/laboratorio/capturas/` | Cinco páginas PTY respaldadas por procesos reales y cuatro capturas Playwright del flujo MFA/acceso/403/revocación. |
| `evidencias/laboratorio/runtime/` | Sólo staging/alerta y copias de trabajo, backup, daño controlado y restauración de fixtures sintéticos. |

## Versiones y límites

- La captura existente registra Python 3.12.3 y SQLite 3.45.1 dentro de `marfil-pdf-test:latest` (ID SHA-256 indicado arriba); esa imagen preexistente se usó con `--pull=never` y no está incluida en los entregables.
- La alternativa consultada es la imagen oficial `python:3.12.13-slim` fijada por digest; se inspeccionó metadata de manifiesto, no se descargó ni ejecutó.
- Docker Engine 29.5.3; red `--internal`, sin puertos publicados, sin rutas de salida externas, código montado como solo lectura y entorno del proceso Python reconstruido con `env -i`.
- Node.js 24.14.1, Playwright Core 1.64.1 y Google Chrome visible 155.0.8059.82; capturas tomadas con `page.screenshot` de páginas vivas.
- Los límites de la ejecución están fijados en el comando Docker: 1 CPU, 256 MiB, 32 procesos, 90 s CPU, 1 MiB por archivo, 64 descriptores y `tmpfs` de 32 MiB. El relé PTY corta una ejecución a los 90 s o 512 KiB de salida.
- La solicitud de 64 KiB es una prueba puntual, **no** evidencia de resistencia a DDoS. La regla de staging es demostrativa, no un SIEM/EDR. El registro SQLite es mutable y no acredita no repudio legal.
- RECOVERY-01 daña de forma controlada un byte de una copia de trabajo, constata que el origen y el backup permanecen intactos, y restaura desde ese backup. Es una **prueba de restauración de archivos**, no una prueba de continuidad del servicio.
- `source_manifest.sha256` hace verificable el código/fixtures que definen las condiciones del laboratorio. No hace que screenshots de navegadores o imágenes de runtime distintos sean píxel a píxel idénticos.
- Terminal.app se consultó mediante AppleScript con límite de 5 s; la enumeración de ventanas no devolvió un ID. No se modificó ni cerró ninguna terminal del usuario y no se usó `screencapture -l`; se tomó la alternativa autorizada de consola web respaldada por PTY real.
- Las cuentas de prueba son fixtures locales; sus valores no se imprimen en logs, resultados ni capturas. No reutilizarlos fuera del laboratorio.
