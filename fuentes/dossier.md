# Dossier de fuentes: plan de ciberseguridad UNA Puno

**Corte documental:** 2026-10-18 (fecha local de consulta). **Alcance:** investigación pública y documental para que la persona autora del informe decida y redacte después. Este dossier no redacta capítulos finales, no afirma controles desplegados ni incidentes de la UNA Puno y no sustituye la validación institucional.

## 1. Resultado útil para la autoría

- Se leyó completa la consigna `TRABAJO 01 Plan_Ciberseguridad.md` (371 líneas). La consigna enumera los apartados y anexos, repite el numeral **XII** para CSF y controles, y no incluye una rúbrica ni ponderaciones de calificación.
- El portal institucional enlaza servicios con los rótulos literales **Matriculas y notas** (`campus.unap.edu.pe`), **Tramites Titulos Grados y Constancias** (`tramites.unap.edu.pe`), **Aula Virtual** (`aulavirtual2.unap.edu.pe`) y **Repositorio Institucional**. Son hechos de catálogo web, no evidencia de disponibilidad, autenticación, arquitectura, responsable técnico o inventario de sistemas.
- El ROF aprobado por Resolución Rectoral N.° 2212-2025-R-UNA define a la **Oficina de Tecnologías de la Información (OTI)** como órgano de apoyo dependiente de Rectorado. Los artículos 70–71 cubren sistemas, infraestructura de cómputo, gobierno digital, telecomunicaciones, redes y seguridad de la información automatizada. Esto fija una responsabilidad orgánica publicada; no prueba que controles concretos estén implementados ni que la jefatura OTI sea el Oficial de Seguridad y Confianza Digital (OSCD).
- Para una matriz CSF 2.0 se proponen resultados específicos en las seis funciones, más abajo. Son **candidatos de mapeo** para que la autoría los adapte a riesgos y evidencias locales; no son equivalencias automáticas ATT&CK↔CSF ni resultados actuales de la UNA.
- Los avisos CISA describen actividad de terceros. Su prioridad como aviso no demuestra exposición local ni un incidente en la UNA. Los indicadores se copian defanged, no se resolvieron ni visitaron y no deben convertirse en reglas de bloqueo sin validación.

## 2. Hechos institucionales y límites

### Servicios publicados

La portada oficial (R01) se identifica como UNAP/UNA Puno y lista esos servicios y enlaces. En particular, la portada no denomina el enlace de trámites como un sistema general de “trámite documentario”: muestra trámites de títulos, grados y constancias. Por separado, el art. 53 del ROF atribuye a Secretaría General conducir procedimientos de trámite documentario. No se debe fusionar ambas afirmaciones ni inferir una plataforma de expediente digital.

| Rótulo literal mostrado en portada | Enlace que publica la portada |
|---|---|
| Matriculas y notas | <https://campus.unap.edu.pe/> |
| Tramites Titulos Grados y Constancias | <https://tramites.unap.edu.pe/> |
| Aula Virtual | <https://aulavirtual2.unap.edu.pe/> |
| Repositorio Institucional | Ruta interna <https://portal.unap.edu.pe/repositorio-institucional>; aplicación enlazada allí: <https://repositorio.unap.edu.pe/> |
| Biblioteca Digital | Ruta interna <https://portal.unap.edu.pe/biblioteca-digital>; aplicación enlazada allí: <https://biblioteca.unap.edu.pe/opac_css/> |

Las URLs se transcriben como destinos de enlaces institucionales publicados; no se hizo prueba de inicio de sesión, funcionamiento, seguridad ni disponibilidad de esas aplicaciones.

**Caveat de integridad de la fuente:** la salida obtenida al leer las dos páginas internas de repositorio y biblioteca incluyó al pie un enlace externo rotulado `bandar togel`. No se siguió el enlace ni se comprobó con navegador independiente; no se atribuye a un incidente. La autoría debe validar con la entidad la integridad de esas páginas antes de reproducir o usar ese elemento. La portada y los rótulos de servicio se conservan como contenido observado, no como auditoría del portal.

### OTI según ROF 2025

- **Art. 70, p. impresa 53:** OTI es órgano de apoyo dependiente de Rectorado, responsable de organizar, diseñar, implementar y gestionar sistemas informáticos, infraestructura tecnológica de cómputo, gobierno digital y telecomunicaciones.
- **Art. 71, pp. impresas 53–54:** propone política informática; identifica necesidades de TIC; evalúa, diseña y desarrolla sistemas; opera sistemas automatizados de información y gestión administrativa; mantiene actualizados los sistemas; establece, implementa y mantiene gobierno digital, telecomunicaciones y redes; mantiene redes/equipos; planifica herramientas digitales; informa a Alta Dirección; capacita en sistemas y vela por la seguridad de la información automatizada.
- El ROF no identifica en esos artículos al OSCD ni al CSIRT institucional. La persona designada para esos roles, los canales de reporte y la relación funcional con OTI requieren validación con la entidad.

### No disponibles en las fuentes públicas consultadas

No se localizó evidencia verificable del inventario real de servidores, estaciones, bases de datos, correo, cámaras, copias, servicios cloud o proveedores; diagramas y flujos; productos y versiones; superficie de exposición; controles existentes (MFA, EDR, SIEM, WAF, firewall, segmentación, cifrado, backups); OSCD/CSIRT designados; registros de incidentes; métricas de base; evidencia de pruebas; vigencia, aprobación o responsables formales del plan. “No localizado” **no significa que no exista**. Debe pedirse a OTI, Alta Dirección, OSCD/CSIRT, responsable de datos personales y unidades dueñas del proceso. La consigna no aporta esos datos y no debe suplirse con conteos o supuestos.

## 3. Marco normativo peruano: alcance y plazos de notificación

| Fuente y artículo | Regla documental comprobada | Condición / límite relevante |
|---|---|---|
| DU 007-2020, arts. 2, 7, 8 y 9.1 (R14) | El art. 2 alcanza a entidades públicas definidas por la Ley 27444, además de otros actores. El art. 7 crea el Centro Nacional de Seguridad Digital (CNSD). El art. 9.1 incluye a las entidades de la Administración Pública entre los sujetos que notifican al CNSD todo incidente de seguridad digital. | El DU no fija por sí solo un único plazo de 48 horas para todo incidente. El art. 9.3 exige SGSI y CSIRT institucional “cuando corresponda”; no prueba que estén implantados en la UNA. |
| DS 126-2025-PCM, arts. 7.2, 9.2, 11.1, 31–34 (R15) | Reglamento del DU 007-2020, publicado el 2025-11-04. El art. 7.2 dispone implementación progresiva del marco institucional; el art. 9.2 dispone evaluar anualmente la gestión de riesgos digital de entidades públicas y conservar resultados; el art. 11.1 asigna al OSCD la coordinación del SGSI, CSIRT institucional y registro/notificación al CNSD. El art. 31.2 fija datos mínimos a notificar (descripción, clasificación, impacto, datos afectados y respuesta inmediata; además IOC/detalles operativos); el 31.1 lista canales oficiales. | **48 horas al CNSD solo para incidentes clasificados críticos**: art. 32.1, desde que el PSD toma conocimiento. Art. 32.2 remite los demás niveles a los plazos de la clasificación emitida por SGTD-PCM. El art. 33.2 exige a entidades públicas clasificar conforme a ella. No presentar 48 h como plazo universal. Verificar clasificación, protocolos y aplicabilidad organizacional antes de escribir el procedimiento. |
| Ley 29733, arts. 9 y 16 (R16) | El principio de seguridad y el art. 16 exigen medidas técnicas, organizativas y legales apropiadas para garantizar seguridad y prevenir alteración, pérdida, tratamiento o acceso no autorizado a datos personales. | La aplicación concreta depende del tratamiento, roles de titular/responsable/encargado, tipos de datos y normas especiales. La ley por sí sola no fija aquí un plazo universal de notificación de incidentes. |
| DS 016-2024-JUS, arts. 34.1, 34.3–34.5 (R17) | Art. 34.1: notificar a la ANPD como máximo en 48 h desde que se toma conocimiento cuando el incidente exponga grandes volúmenes por cantidad o tipo, pueda afectar a muchas personas, involucre datos sensibles o cause perjuicio evidente a otros derechos/libertades. La obligación de notificar a la ANPD persiste aunque el incidente se haya subsanado. Art. 34.3: si el incidente afecta a la persona titular en otros derechos, comunicarlo a esa persona sin dilación indebida y dentro de 48 h; si se supera el plazo, justificar. Art. 34.5 añade notificación al CNSD si ocurre en/mediante entorno digital. | **48 h es condicional y hay deberes distintos**: ANPD (art. 34.1) frente a persona titular (art. 34.3). El art. 34.4 exime de comunicar al titular cuando no ocurrió la afectación descrita y el incidente fue superado totalmente; no debe confundirse con la excepción al aviso a la ANPD. Coordinar el art. 34.5 con DU 007-2020 y DS 126-2025-PCM. |

**Hallazgo de gobernanza para validar:** OTI tiene funciones informáticas y de seguridad de información automatizada en ROF; DS 126-2025-PCM asigna otras funciones al OSCD formalmente designado. No afirmar que ambos roles son la misma persona/unidad sin resolución o evidencia institucional.

## 4. Candidatos de CSF 2.0 para la matriz de la persona autora

NIST CSF 2.0 define las seis funciones: **GOVERN** (estrategia, expectativas y política de riesgo); **IDENTIFY** (comprensión del riesgo actual); **PROTECT** (salvaguardas); **DETECT** (hallar y analizar ataques/compromisos); **RESPOND** (acciones frente al incidente); **RECOVER** (restaurar activos y operaciones). Para empezar la matriz —no como evaluación de estado actual— se proponen subcategorías con texto exacto NIST:

| Función | Categoría/subcategorías candidatas (texto NIST) | Uso que la autoría puede evaluar |
|---|---|---|
| Govern | GV.RR-02: roles, responsabilidades y autoridades de riesgo cibernético se establecen, comunican, entienden y hacen cumplir. GV.RM-01: objetivos de gestión de riesgo se establecen y acuerdan con partes interesadas. | Designación, autoridad, aprobación y recursos del plan; confirmar nombres y resoluciones. |
| Identify | ID.AM-01: inventarios de hardware mantenidos. ID.AM-02: inventarios de software, servicios y sistemas mantenidos. ID.RA-01: vulnerabilidades de activos identificadas, validadas y registradas. | Levantar inventario, propietarios, criticidad y vulnerabilidades; no inferirlo de la lista de portal. |
| Protect | PR.AA-03: usuarios, servicios y hardware autenticados. PR.PS-02: software mantenido, reemplazado y retirado según riesgo. PR.AT-01: personal recibe sensibilización y capacitación para tareas generales con conocimiento de riesgos cibernéticos. | Controles de acceso, parcheo y formación; diseñar como acciones propuestas hasta conseguir evidencia. |
| Detect | DE.CM-01: redes y servicios de red monitoreados para hallar eventos potencialmente adversos. DE.AE-02: eventos potencialmente adversos analizados para entender actividades asociadas. | Necesidades de telemetría, revisión y análisis, sin afirmar que exista SIEM/EDR. |
| Respond | RS.MA-01: plan de respuesta ejecutado coordinando con terceros pertinentes una vez declarado un incidente. RS.CO-02: partes interesadas internas y externas notificadas. | Roles, escalamiento y obligaciones legales; hacer concordar los plazos condicionales de R15/R17. |
| Recover | RC.RP-01: parte de recuperación del plan ejecutada al iniciarse desde el proceso de respuesta. RC.CO-03: actividades y progreso de recuperación comunicados a partes interesadas designadas. | Restauración y comunicación; exigir evidencia de pruebas de restauración para medir capacidad real. |

Los subcódigos son resultados NIST y no controles ya implantados. Las relaciones con ATT&CK o STRIDE son una decisión analítica posterior respaldada por escenario/evidencia, no una equivalencia nativa del CSF.

R07 respalda la secuencia de Cyber Kill Chain **Reconnaissance → Weaponization → Delivery → Exploitation → Installation → Command & Control → Actions on Objectives** (reconocimiento, armamentización/armamento, entrega, explotación, instalación, comando y control, acciones sobre objetivos). La secuencia es un modelo analítico; no debe presentarse como fases observadas en una intrusión contra la UNA.

## 5. Fichas documentales para el boletín de inteligencia

Las fichas resumen avisos verificados, no incidentes locales. `Prioridad del aviso` y `exposición UNA` se mantienen separadas.

### B01 — Explotación activa de BeyondTrust Remote Support

- **Fuente/fecha:** CISA, *CISA Urges Patching Critical Vulnerability in BeyondTrust Remote Support*, 2026-10-16 (R19); CVE-2026-102764.
- **Hecho del aviso:** bypass crítico de autenticación que afecta BeyondTrust Remote Support (antes Bomgar) hasta versión 26.2.3. Parches disponibles para versiones soportadas 24.3.1 o posteriores; instalaciones anteriores necesitan primero actualizar. CISA dice que atacantes lo explotan activamente y lo agregó a KEV el 2026-10-16. CISA indica que las implementaciones SaaS alojadas ya se parchearon.
- **Prioridad del aviso:** alta/urgente según la propia advertencia CISA; verificar inventario y parche/actualización solo si coincide producto, modalidad y versión.
- **Exposición UNA:** no verificada. No se encontró fuente que demuestre que la UNA use ese producto, sea autoalojado, esté expuesto o esté comprometido. El aviso no publica IOC ni etiqueta una versión ATT&CK; no asignar una por inferencia.

### B02 — Gunra ransomware (doble extorsión)

- **Fuente/fecha:** CISA, FBI, DC3, NSA, USSS y KNPA, *#StopRansomware: Gunra Ransomware*, AA26-222A, publicado 2026-08-10 (R20).
- **Hecho del aviso:** Gunra opera como RaaS; agencias describen cifrado y amenaza de publicar datos exfiltrados. El aviso incluye entre los sectores víctimas la academia. Recomienda parcheo de vulnerabilidades explotadas en servicios internet-facing, backups offline/inmutables probados y segmentación.
- **ATT&CK:** el propio aviso conserva su referencia **ATT&CK v19.1**; entre sus mapeos cita T1083, T1005 y T1078.001/.002. Para una matriz actual, comparar el ID y título con la versión v20.0 (R08–R13), sin reescribir retroactivamente la versión citada por CISA.
- **Prioridad del aviso:** pertinente para preparación de ransomware/doble extorsión; la mención de academia es contexto sectorial, no un ataque a la UNA.
- **Exposición UNA:** no verificada. El aviso advierte que IP/dominios pueden ser históricos y deben verificarse antes de bloquear.

### B03 — Actividad de actores chinos con escaneo, XSS y robo de datos

- **Fuente/fecha:** CISA y agencias asociadas, *Chinese Government-linked Cyber Threat Actors Combine Automated and Hands-on Hacking Tools to Steal Sensitive Data*, AA26-281A, publicado 2026-10-08 (R18).
- **Hecho del aviso:** el resumen registra explotación/escaneo, XSS, password spraying contra Exchange, persistencia por clientes VPN y exfiltración de correo/credenciales. Nombra educación entre organizaciones afectadas en las observaciones descritas, además de varios sectores críticos. Recomienda deshabilitar servicios no usados, sanitizar entrada web, MFA y parcheo.
- **ATT&CK:** la advertencia dice expresamente **version 19**. Su texto atribuye T1189 a la técnica XSS/drive-by compromise y T1074.001 a la localización donde un script busca un directorio escribible. **No** reinterpretar esta actividad como T1566 (phishing de correo) sin evidencia; T1566 se conserva como taxonomía aparte (R13).
- **Prioridad del aviso:** útil para el análisis de robo de credenciales/datos y superficie web; su alcance sectorial no valida exposición ni incidente en la UNA.
- **Exposición UNA:** no verificada. No se identificó despliegue de Exchange, clientes VPN, sistemas vulnerables ni comportamiento equivalente en telemetría UNAP.

### Indicadores copiados de los avisos (defanged; no visitados)

| Fuente | Tipo | Valor defanged | Contexto y fecha observada/publicada | Confianza / limitación de la fuente |
|---|---|---|---|---|
| R18 | Dominio | `dns[.]studiocloud[.]xyz` | CISA AA26-281A (2026-10-08): el ejecutable `live700_v1.exe` inicia `DiagTrack.exe`, que establece comunicación HTTP cifrada; el texto atribuye el dominio al FBI/Integrity Tech. | El informe describe el hallazgo/atribución, pero no da puntuación numérica de confianza ni fechas de first/last seen por indicador. No se resolvió ni visitó el dominio. |
| R20 | IPv4 | `23.239.119[.]2` | Tabla 2 del aviso Gunra: primera observación “July 2025”, última “Nov. 6, 2025”. | Aviso conjunto incluye el indicador como asociado con infraestructura Gunra, sin puntuación individual numérica; advierte que puede ser histórico y recomienda validarlo antes de bloquear. No se consultó la IP. |

No se presenta ningún IOC como activo en la fecha de consulta ni como indicador hallado en sistemas UNAP. La alerta BeyondTrust (R19) no publica IOC; no se inventa uno.

## 6. Checklist de fuentes y datos pendientes por apartado

| Consigna | Fuentes de base | Evidencia institucional que aún debe obtenerse (si se redacta el informe) |
|---|---|---|
| I–V: datos generales, introducción, finalidad, objetivos y alcance | R01–R05, R14–R17 | Responsable y aprobación formal del plan, periodo de vigencia, alcance acordado y autoridad competente. No inferirlos del ROF. |
| VI: inventario y clasificación | R01–R03, R15 | Inventario real, dueños, datos, criticidad, dependencias, terceros y clasificación aprobada. La portada solo prueba enlaces publicados. |
| VII: STRIDE | R06 | Diagramas/flujo de datos y límites de confianza para cada sistema seleccionado; amenazas y controles actuales. R06 aporta vocabulario, no modelo UNAP. |
| VIII: inteligencia de amenazas | R18–R20 | Proceso institucional, fuentes, clasificación, responsable, ventanas de vigencia y protocolo local de recepción/validación. Los avisos son externos. |
| IX: ATT&CK | R08–R13, R18, R20 | Escenarios relevantes, datos de telemetría, cobertura de detección y versión del catálogo citada. Evitar mapear TTP si el aviso no lo hace. |
| X: Cyber Kill Chain | R07, R18, R20 | Aplicación conceptual a un escenario documentado; no inventar fases observadas en la UNA. |
| XI: Zero Trust | R04, R12 | Identidades, dispositivos, recursos, política de acceso y estado de MFA/privilegios; nada de eso se confirma con el portal. |
| XII CSF 2.0 / controles | R03–R05, R15, R17–R20 | Perfil actual/objetivo, responsables, herramientas y estado de cada resultado. Las subcategorías propuestas no son controles implantados. |
| Gestión de incidentes y registro | R05, R14–R17 | OSCD y CSIRT designados, canales, protocolos/clasificación SGTD, procedimiento de datos personales, contratos y registros reales. |
| Capacitación, indicadores y cronograma | R03, R13, R15, R20 | Plan aprobado, audiencias, asistencia, ejercicios, línea de base y series de medición. No inventar porcentajes ni tiempos. |
| Anexos 1–10 | R01–R20 según el producto | Requieren datos/evidencia local; esta ejecución no crea inventarios, capturas de pruebas, registros de incidentes, métricas ni cronogramas institucionales. |

## 7. Registro bibliográfico R01–R20

Todas las referencias se consultaron el **2026-10-18**. Las fechas son las visibles en la fuente; cuando no se muestra día/mes se conserva la precisión disponible.

### Institución y marcos

- **R01 — Portada institucional de la Universidad Nacional del Altiplano Puno.** Institución: Universidad Nacional del Altiplano Puno. Fecha editorial visible: no indicada (página dinámica). URL: <https://portal.unap.edu.pe/>. Sustento: encabezado UNA Puno y menú de servicios citado en §2. Límite: lista publicada, no prueba operación o arquitectura.
- **R02 — Reglamento de Organización y Funciones (aprobado por Resolución Rectoral N.° 2212-2025-R-UNA).** Institución: Universidad Nacional del Altiplano. Fecha: 2025; la copia consultada no muestra día de aprobación. URL PDF: <https://portal.unap.edu.pe/sites/default/files/2025-10/ROF-modificado-aprobado-por-RR-2212-2025-R-UNA.pdf>. Pinpoint: arts. 53, 70–71; pp. impresas 53–54. Copia local: `documentos/ROF-2025-RR-2212.pdf`. Límite: distribución formal de funciones, no evidencia de ejecución.
- **R03 — The NIST Cybersecurity Framework (CSF) 2.0, NIST CSWP 29.** Institución: NIST. Fecha: 2024-02-26. URL institucional: <https://www.nist.gov/cyberframework>; PDF <https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf>. Sustento: seis funciones y Core, pp. 1–2 y 17–22. Copia local: `documentos/NIST-CSF-2.0-CSWP-29.pdf`. Límite: marco de resultados; no mide a la UNA.
- **R04 — Zero Trust Architecture, NIST SP 800-207.** Institución: NIST. Publicación final: 2020-08-11. URL: <https://csrc.nist.gov/pubs/sp/800/207/final>; PDF <https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-207.pdf>. Sustento: no existe confianza implícita basada solo en ubicación de red/propiedad; autenticar y autorizar sujeto y dispositivo antes de sesión a recursos. Copia local: `documentos/NIST-SP-800-207.pdf`. Límite: guía de arquitectura, no certificación/estado de la UNA.
- **R05 — Incident Response Recommendations and Considerations for Cybersecurity Risk Management: A CSF 2.0 Community Profile, NIST SP 800-61 Rev. 3.** Institución: NIST. Publicación final: 2025-04-03. URL: <https://csrc.nist.gov/pubs/sp/800/61/r3/final>; PDF <https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r3.pdf>. Sustento: integra respuesta a incidentes en las seis funciones CSF 2.0; preparación amplia y mejora continua. Copia local: `documentos/NIST-SP-800-61r3.pdf`. Límite: recomendaciones, no procedimiento aprobado para UNAP.
- **R06 — Threats - Microsoft Threat Modeling Tool (STRIDE).** Institución: Microsoft Learn/Microsoft SDL. Publicación original visible: 2017-08-17; actualización visible: 2026-03-04. URL: <https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats>. Sustento: define Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service y Elevation of Privilege. Límite: taxonomía asociada a herramienta/modelado Microsoft; no análisis de sistemas UNA.
- **R07 — Cyber Kill Chain® / Gaining the Advantage: Applying Cyber Kill Chain® Methodology.** Institución: Lockheed Martin. Fecha editorial visible: no indicada en la página consultada. URL institucional: <https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html>; guía PDF <https://www.lockheedmartin.com/content/dam/lockheed-martin/rms/documents/cyber/Gaining_the_Advantage_Cyber_Kill_Chain.pdf>. Sustento: metodología de siete fases y guía original. Copia local: `documentos/LockheedMartin-Cyber-Kill-Chain-Guide.pdf`. Límite: modelo conceptual; no establece que una fase haya ocurrido en UNAP.
- **R08 — ATT&CK Version History.** Institución: MITRE. Versión vigente visible: ATT&CK v20.0 desde 2026-10-13; v19.2 vigente hasta 2026-10-12. URL: <https://attack.mitre.org/resources/versions/>. Sustento: historial/versionado oficial. Límite: utilizar la versión que cada aviso declara; no sustituir el mapping histórico sin revalidarlo.

### Taxonomía ATT&CK Enterprise (permalinks v20.0)

- **R09 — File and Directory Discovery (T1083).** Institución: MITRE ATT&CK. Modificación visible: 2026-09-11. URL: <https://attack.mitre.org/versions/v20/techniques/T1083/>. Sustento: enumeración/búsqueda de archivos y directorios, táctica Discovery. Límite: no prueba actividad en UNAP.
- **R10 — Data from Local System (T1005).** Institución: MITRE ATT&CK. Modificación visible: 2026-09-11. URL: <https://attack.mitre.org/versions/v20/techniques/T1005/>. Sustento: búsqueda de datos locales antes de exfiltración, táctica Collection. Límite: taxonomía, no evidencia institucional.
- **R11 — Data Staged: Local Data Staging (T1074.001).** Institución: MITRE ATT&CK. Modificación visible: 2026-09-11. URL: <https://attack.mitre.org/versions/v20/techniques/T1074/001/>. Sustento: staging local antes de exfiltración, táctica Collection. Límite: no equiparar automáticamente un archivo temporal legítimo con esta técnica.
- **R12 — Valid Accounts (T1078).** Institución: MITRE ATT&CK. Modificación visible: 2026-05-12. URL: <https://attack.mitre.org/versions/v20/techniques/T1078/>. Sustento: abuso de credenciales de cuentas existentes; incluye sub-técnicas default/domain/local/cloud. Límite: escoger sub-técnica solo con evidencia del método de cuenta.
- **R13 — Phishing (T1566).** Institución: MITRE ATT&CK. Modificación visible: 2026-09-18. URL: <https://attack.mitre.org/versions/v20/techniques/T1566/>. Sustento: phishing como acceso inicial; separa adjunto, enlace, servicio y voz. Límite: no atribuir phishing a un aviso que solo documenta XSS/credential harvesting.

### Normativa peruana

- **R14 — Decreto de Urgencia N.° 007-2020, que aprueba el Marco de Confianza Digital.** Institución: Presidencia del Consejo de Ministros. Fecha: 2020-01-09. URL legal: <https://www.gob.pe/institucion/pcm/normas-legales/395322-007-2020>; PDF <https://cdn.www.gob.pe/uploads/document/file/2790485/Decreto%20de%20Urgencia%20N%C2%BA%20007-2020.pdf?v=1643322610>. Sustento: arts. 2, 7–9. Copia local: `documentos/DU-007-2020.pdf`. Límite: el DU por sí solo no impone un plazo plano de 48 h a toda categoría de incidente.
- **R15 — Decreto Supremo N.° 126-2025-PCM y Reglamento del DU 007-2020.** Institución: Presidencia del Consejo de Ministros/SGTD. Fecha: 2025-11-04. URL legal: <https://www.gob.pe/institucion/pcm/normas-legales/7370829-126-2025-pcm>; decreto PDF <https://cdn.www.gob.pe/uploads/document/file/8953630/7370829-1-ds-n-126-2025-pcm%282%29.pdf?v=1767577371>; reglamento PDF <https://cdn.www.gob.pe/uploads/document/file/8993787/7370829-2-reglamento.pdf?v=1763064968>. Sustento: arts. 7.2, 9.2, 11.1, 31–34. Copias locales: `documentos/DS-126-2025-PCM.pdf`, `documentos/Reglamento-DU-007-2020-DS126-2025-PCM.pdf`. Límite: verificar rol formal OSCD/CSIRT, clasificación y canales actuales en UNAP.
- **R16 — Ley N.° 29733, Ley de Protección de Datos Personales.** Institución: Autoridad Nacional de Protección de Datos Personales/Ministerio de Justicia y Derechos Humanos. Fecha: 2011-07-03. URL legal: <https://www.gob.pe/institucion/anpd/normas-legales/2018427-29733-2011>; PDF <https://cdn.www.gob.pe/uploads/document/file/2011398/Ley%20N%C2%BA%2029733%20-%20Ley%20de%20protecci%C3%B3n%20de%20datos%20personales.pdf.pdf?v=1683928275>. Sustento: arts. 9 y 16. Copia local: `documentos/Ley-29733.pdf`. Límite: confirmar tratamientos, roles, tipo/volumen de datos y normas especiales.
- **R17 — Decreto Supremo N.° 016-2024-JUS, Reglamento de la Ley 29733.** Institución: ANPD/Ministerio de Justicia y Derechos Humanos. Fecha: 2024-11-30. URL legal: <https://www.gob.pe/institucion/anpd/normas-legales/6554453-16-2024-jus>; PDF <https://cdn.www.gob.pe/uploads/document/file/7756037/6554453-reglamento-de-la-ley-n-29733.pdf?v=1743779969>. Sustento: art. 34, en especial 34.1 y 34.3–34.5. Copia local: `documentos/DS-016-2024-JUS-Reglamento-Ley29733.pdf`. Límite: los umbrales de 34.1 y la afectación descrita en 34.3 son condiciones; no resumirlo como “todo incidente se notifica en 48 h”.

### Avisos de inteligencia

- **R18 — AA26-281A, Chinese Government-linked Cyber Threat Actors Combine Automated and Hands-on Hacking Tools to Steal Sensitive Data.** Institución: CISA y organismos asociados. Publicación: 2026-10-08. URL: <https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-281a>; PDF <https://www.cisa.gov/sites/default/files/2026-10/chinese-government-linked-cyber-threat-actors-combine-automated-and-hands-on-hacking-tools-to-steal-sensitive-data-508c.pdf>. Sustento: Executive Summary, initial access/persistence/collection, Tabla MITRE y Appendix A. Copia local: `documentos/CISA-AA26-281A.pdf`. Límite: el aviso cita ATT&CK “version 19”; no indica incidente UNAP ni puntaje de confianza IOC.
- **R19 — CISA Urges Patching Critical Vulnerability in BeyondTrust Remote Support.** Institución: CISA. Publicación: 2026-10-16. URL: <https://www.cisa.gov/news-events/alerts/2026/10/16/cisa-urges-patching-critical-vulnerability-beyondtrust-remote-support>. Sustento: versión afectada, parche BT26-05-RS, condición self-hosted/SaaS, explotación activa y alta en KEV. Límite: no menciona UNAP y no publica IOC ni versión ATT&CK.
- **R20 — AA26-222A, #StopRansomware: Gunra Ransomware.** Institución: CISA, FBI, DC3, NSA, USSS y KNPA. Publicación: 2026-08-10. URL: <https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-222a>; PDF <https://www.cisa.gov/sites/default/files/2026-08/aa26-222a-stopransomware-gunra-ransomware_508c.pdf>. Sustento: Executive Summary, sectores, mitigaciones, Tabla 2 IOCs y tablas MITRE. Copia local: `documentos/CISA-AA26-222A-Gunra.pdf`. Límite: el aviso usa ATT&CK v19.1 y advierte que los IOC pueden ser históricos; no es un incidente UNAP.

## 8. Descargas y manifiesto

Se descargaron 12 PDF oficiales enlazados por las fuentes primarias con `curl -fL` el 2026-10-18. Tamaño agregado medido: **16,168,712 bytes** (15.4 MiB), inferior al límite solicitado de 30 MB. Los SHA-256 completos están en [`documentos/SHA256SUMS`](documentos/SHA256SUMS) y se reproducen en `dossier.json`. Los PDFs se conservaron como referencia local; no se descargaron muestras maliciosas ni archivos STIX/IOC separados.

## 9. Advertencias de uso para el informe posterior

1. Separar siempre **hecho observado en una fuente**, **requisito normativo**, **propuesta de control** y **estado UNAP pendiente de validar**.
2. Citar el ROF para la competencia OTI, pero validar resolución de designación del OSCD, CSIRT y responsable del plan antes de nombrarlos.
3. No afirmar existencia o ausencia de incidentes, equipos, proveedores, tecnologías o controles a partir del portal público.
4. Para los dos avisos que usan MITRE v19/v19.1, mantener esa versión en la ficha; v20.0 pasó a ser versión actual el 2026-10-13 (R08). Revalidar títulos/mapeos antes de trasladarlos a la matriz vigente.
5. Respetar la diferencia entre plazo crítico a CNSD del DS 126-2025-PCM y notificaciones condicionales de datos personales del DS 016-2024-JUS.
