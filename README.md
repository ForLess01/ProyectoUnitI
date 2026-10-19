# Plan de ciberseguridad — UNA Puno

**Asignatura:** Tópicos de Ciberseguridad · Unidad I

**Docente:** Ing. Fidel Ernesto Ticona Yanqui

**Estudiante:** Alfonte Tarqui Rendo

Plan aplicado a la Universidad Nacional del Altiplano de Puno, con investigación documental, matrices de gestión del riesgo y pruebas reales en un laboratorio aislado con datos ficticios. Las pruebas locales no constituyen una auditoría de la infraestructura universitaria.

## Informe

- [PDF para lectura y entrega](entrega/Informe_Plan_Ciberseguridad_UNA_Puno.pdf)
- [Fuente LaTeX](entrega/Informe_Plan_Ciberseguridad_UNA_Puno.tex)

El informe incluye los diez anexos de la consigna, glosario, referencias, comandos, 14 capturas originales documentadas y resultados de 13 casos funcionales y cuatro flujos de navegador. Montserrat se incluye con su licencia OFL y se incrusta en el PDF.

## Compilación

Desde la raíz del repositorio, con XeLaTeX y latexmk disponibles:

```sh
bash herramientas/latex/compile_report.sh
```

Las rutas de imágenes y fuentes se resuelven desde la raíz. No es necesario instalar Montserrat globalmente.

## Organización

| Directorio | Contenido |
|---|---|
| `entrega/` | Informe LaTeX y PDF compilado. |
| `evidencias/web/` | Capturas de páginas públicas de la universidad y registro de navegación. |
| `evidencias/laboratorio/` | Capturas técnicas, resultados, logs y manifiestos SHA-256. |
| `laboratorio/` | Código, pruebas y fixtures; guía de reproducción y límites del entorno. |
| `fuentes/` | Registro de referencias y copias documentales oficiales. |
| `recursos/` | Montserrat y detalles geométricos de capturas para lectura. |
| `herramientas/` | Scripts de captura, composición y verificación. |

## Evidencia y reproducción

Las ejecuciones técnicas usaron Docker con red interna, recursos limitados y código de solo lectura. La consola PTY ejecutó procesos reales; las imágenes no reconstruyen salidas. Los recortes de lectura conservan los originales y registran su relación por hash.

Los detalles de reproducción se encuentran en [`laboratorio/README.md`](laboratorio/README.md). La imagen local exacta de la corrida no se distribuye; su identidad está registrada y se documenta una alternativa oficial sin afirmar que produzca una reconstrucción idéntica del entorno original.

Los datos institucionales públicos, los controles propuestos y los resultados de laboratorio están separados en el informe. El Aula Virtual devolvió HTTP 502 durante dos intentos de captura: se conserva el registro y no se atribuye una causa ni se fabrica una imagen.

## Integridad

`evidencias/laboratorio/manifest.sha256` registra las 41 evidencias finales; `source_manifest.sha256` registra 16 archivos técnicos. Las verificaciones se interpretan respecto de las rutas indicadas y no sustituyen una firma digital ni una cadena de custodia institucional.

Las fuentes oficiales y Montserrat conservan su procedencia. La inclusión de documentos institucionales no implica autoría sobre ellos ni aprobación del plan por la universidad.
