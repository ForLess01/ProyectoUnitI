# Suplemento de referencias R21–R25 y comprobación NIST PR.AA-05

**Propósito:** complementar el dossier bibliográfico R01–R20 sin modificarlo. URLs contrastadas con páginas oficiales el 18/10/2026. Este suplemento no forma parte del manifiesto de evidencia del laboratorio.

| Ref. | Fuente primaria y fecha | URL | Pinpoint, aporte y límite |
|---|---|---|---|
| R21 | FBI/CISA, *Cyber Threat Actors Use a Variety of Techniques to Target Election and Campaign Officials*, PSA I-101626-PSA, 16/10/2026. | [IC3 PSA](https://www.ic3.gov/PSA/2026/PSA261016) | El PSA habla de phishing/smishing contra autoridades electorales y de campaña de EE. UU. Sustenta TI-04; no prueba campaña ni exposición en UNA Puno. |
| R22 | IETF RFC 6238, *TOTP: Time-Based One-Time Password Algorithm*, mayo de 2011. | [RFC Editor](https://www.rfc-editor.org/rfc/rfc6238) | Apéndice B: a t=59, SHA-1, 8 dígitos, vector `94287082`. No presenta `287082` como vector independiente de 6 dígitos; es el valor reducido a 6 dígitos que informa el laboratorio. |
| R23 | Microsoft/Playwright, documentación *Screenshots*; no indica fecha editorial en la página. Consulta: 18/10/2026. | [Playwright Screenshots](https://playwright.dev/docs/screenshots) | Documenta `page.screenshot`, página completa y captura de elemento. Explica la API, no autentica por sí sola una captura ni demuestra una ejecución. |
| R24 | MITRE ATT&CK Enterprise, *Exploitation for Privilege Escalation*, T1068. Creada 31/05/2017; página v20 modificada 24/10/2025; v20.0 vigente desde 13/10/2026 según R08. | [ATT&CK v20 T1068](https://attack.mitre.org/versions/v20/techniques/T1068/) | Define explotación de vulnerabilidades para elevar privilegios. Sustenta el nombre/concepto del escenario de Anexo 4; no acredita explotación en la UNA. |
| R25 | MITRE ATT&CK Enterprise, *Remote Services*, T1021. Creada 31/05/2017; página v20 modificada 24/10/2025; v20.0 vigente desde 13/10/2026 según R08. | [ATT&CK v20 T1021](https://attack.mitre.org/versions/v20/techniques/T1021/) | Describe el uso adversario de servicios remotos, incluido el movimiento lateral. Sustenta la etiqueta del escenario de Anexo 4; no acredita actividad en la UNA. |

## Comprobación del cross-trace NIST PR.AA-05

La fuente existente **R03**, NIST CSWP 29, *The NIST Cybersecurity Framework (CSF) 2.0*, se publicó el 26/02/2024. En el Apéndice A, función PROTECT, categoría PR.AA, la subcategoría **PR.AA-05** dice textualmente:

> “Access permissions, entitlements, and authorizations are defined in a policy, managed, enforced, and reviewed, and incorporate the principles of least privilege and separation of duties.”

Fuente primaria: [DOI 10.6028/NIST.CSWP.29](https://doi.org/10.6028/NIST.CSWP.29) · [PDF NIST](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf).

**Resultado:** el código y su relación analítica con C02 y los escenarios S03/S07/S11 del TEX son pertinentes. La frase del TEX “permisos revisados y mínimo privilegio por recurso” es una síntesis en español, no una traducción literal: recoge revisión y mínimo privilegio, pero no expresa toda la política, gestión/aplicación ni separación de funciones del resultado NIST. No se modificó el TEX.
