# Montserrat: procedencia y uso

Los archivos estáticos de Montserrat se obtuvieron por HTTPS del repositorio de
la tipografía mantenido por Julieta Ulanovsky y el equipo de Montserrat, fijado
al commit `cc8daf2e7085006b9c112542fc82b58afc13521d`.

Google Fonts identifica ese repositorio y commit como fuente ascendente de su
familia Montserrat:

- Registro de Google Fonts:
  <https://github.com/google/fonts/blob/main/ofl/montserrat/upstream_info.md>
- Repositorio de origen fijado al commit:
  <https://github.com/JulietaUla/Montserrat/tree/cc8daf2e7085006b9c112542fc82b58afc13521d>
- Archivos estáticos TTF:
  <https://github.com/JulietaUla/Montserrat/tree/cc8daf2e7085006b9c112542fc82b58afc13521d/fonts/ttf>

Se incluyen Regular, Bold, Italic, Bold Italic, SemiBold y SemiBold Italic.
La licencia SIL Open Font License 1.1 se conserva en `OFL.txt`; las sumas
SHA-256 de las fuentes y la licencia están en `SHA256SUMS`.

Las fuentes se cargan desde este proyecto mediante `fontspec`; no se instalan
en el sistema. El estilo falla explícitamente si falta alguna cara requerida,
en vez de sustituirla por una fuente del sistema.
