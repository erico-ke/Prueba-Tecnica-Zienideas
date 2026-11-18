# 🛡️ Detector de concesiones de permisos fraudulentas

**Prueba técnica · IRISHAWK Cybersecurity** · Python · Microsoft Graph · solo lectura

> Herramienta que se conecta a un tenant de Microsoft 365 / Entra ID con una aplicación registrada y permisos de **solo lectura**, y localiza **permisos que no deberían existir**. Detecta sobre todo el *consent phishing* (*illicit consent grant*): un atacante consigue que alguien autorice una app maliciosa que después lee correo y archivos **sin contraseña ni MFA**.
>
> Se usa desde la línea de comandos o desde una ventana de escritorio, y genera informes en HTML, JSON y CSV.

---

## Índice

1. [Para quién es](#1-para-quién-es)
2. [Qué detecta](#2-qué-detecta)
3. [Puesta en marcha](#3-puesta-en-marcha)
4. [Hallazgos en el tenant de pruebas](#4-hallazgos-en-el-tenant-de-pruebas)
5. [Memoria](#5-memoria)
   - [5.1 Del enunciado al producto](#51-del-enunciado-al-producto)
   - [5.2 Línea de pensamiento](#52-línea-de-pensamiento)
   - [5.3 Criterio de la puntuación](#53-criterio-de-la-puntuación)
   - [5.4 Falsos positivos](#54-falsos-positivos)
   - [5.5 Lo que revelaron los datos](#55-lo-que-revelaron-los-datos)
   - [5.6 Privacidad](#56-privacidad)
   - [5.7 Errores de la IA y cómo los corregí](#57-errores-de-la-ia-y-cómo-los-corregí)
   - [5.8 Qué haría con más tiempo](#58-qué-haría-con-más-tiempo)
6. [Arquitectura](#6-arquitectura)
7. [Seguridad de la propia herramienta](#7-seguridad-de-la-propia-herramienta)

---

## 1. Para quién es

La diseñé para un **auditor, pentester o analista de seguridad** cuyo trabajo es **localizar y dejar registrados los permisos que no deberían existir** en un tenant: apps con más acceso del necesario, consentimientos que nadie recuerda haber dado y credenciales que nadie controla.

| Esa persona necesita… | …y por eso la herramienta tiene |
|---|---|
| Saber **qué mirar primero** | Severidades y una **puntuación de riesgo** por app |
| **Entender y defender** cada alerta ante el cliente | Cada indicador se muestra **con su peso** (`+3 nombre que imita a Microsoft`) |
| **Dejar constancia** del hallazgo | Exportación a HTML, JSON y CSV con **IDs estables** para abrir incidencias |
| Revisar **en directo** | Una **interfaz gráfica** con los permisos indebidos marcados en rojo |

---

## 2. Qué detecta

### 🎯 Concesiones sospechosas: puntuación de riesgo por aplicación

Cada aplicación que no es de Microsoft suma puntos por cada indicador que cumple. **Ningún indicador por sí solo prueba un fraude: lo que lo delata es la combinación.**

| Puntos | Indicador |
|:---:|---|
| **+3** | Nombre que imita a Microsoft (Office, Outlook, Azure, Teams…), solo en apps de otros tenants |
| **+3** | Permisos de aplicación de alto impacto (escritura o contenido sensible: correo, archivos, chats, Copilot…) |
| **+3** | Credenciales añadidas a la app de un tercero (posible puerta trasera) |
| **+2** | Editor no verificado (solo terceros) |
| **+2** | Permisos delegados sensibles consentidos (`Mail.Read`, `Files.Read.All`, `Directory.ReadWrite.All`…) |
| +1 | App de otro tenant (tercero) |
| +1 | Consentimiento para **toda la organización** |
| +1 | Acceso persistente (`offline_access`) |
| +1 | Creada hace menos de 30 días |
| +1 | URL de respuesta `http://` (no localhost) |

| Puntuación | Severidad |
|:---:|---|
| 8 o más | 🟥 **Crítica** (un consent phishing de manual suma 10) |
| 5 – 7 | 🟧 **Alta** |
| 3 – 4 | 🟨 **Media** |
| menos de 3 | Solo inventario |

**Apps de Microsoft:** no se puntúan como fraude, pero tienen dos reglas propias:
- 🟧 **Credenciales añadidas a una app de Microsoft**: técnica de persistencia conocida (Solorigate).
- 🟨 **Herramientas de Microsoft con permisos delegados peligrosos**: por ejemplo, Graph Explorer con `Directory.ReadWrite.All`. No es fraude, pero un token robado de esa sesión da ese poder.

### 🔍 Además

| Área | Qué revisa |
|---|---|
| **Permisos de la propia herramienta** | Escritura, lectura de contenido sensible, permisos innecesarios, delegados sin uso. Un detector de permisos excesivos tiene que pasar su propio examen. |
| **Acceso real frente a permisos** | Prueba 21 endpoints. Detecta los accesibles **sin** el permiso documentado y los permisos concedidos que no funcionan por falta de licencia (**privilegio latente**). |
| **Registros de aplicaciones** | Secretos que caducan o con validez de más de 12 meses, apps sin propietario, varias credenciales activas, URIs `http://` |
| **Organización y gobierno** | Licencia Entra ID P1/P2, contactos de seguridad y privacidad, revisiones de acceso |

---

## 3. Puesta en marcha

### 3.1 Registrar la aplicación en Entra ID

1. [entra.microsoft.com](https://entra.microsoft.com) → **Aplicaciones** → **Registros de aplicaciones** → **Nuevo registro**.
2. **Permisos de API** → **Agregar un permiso** → **Microsoft Graph** → **Permisos de aplicación** → **`Application.Read.All`**. Es el único permiso necesario.
   > ⚠️ Tiene que ser de tipo **Aplicación**, no *Delegado*. Con delegados el token llega sin permisos y todo da 403.
3. **Conceder consentimiento de administrador**. Debe quedar con el check verde.
4. **Certificados y secretos** → **Nuevo secreto de cliente**. Copia la columna **Valor**, porque solo se muestra una vez.

### 3.2 Instalar y configurar

Requiere Python 3.10 o superior.

```bash
python3 -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env                 # rellenar TENANT_ID, CLIENT_ID y CLIENT_SECRET
```

| Variable | Dónde está | Error típico |
|---|---|---|
| `TENANT_ID` | Información general → *Id. de directorio (inquilino)*. También vale `xxx.onmicrosoft.com` | Copiar el *Id. de objeto* o el *Subscription ID* |
| `CLIENT_ID` | Información general → *Id. de aplicación (cliente)* | Copiar el *Id. de objeto* |
| `CLIENT_SECRET` | Columna *Valor* del secreto | Copiar el *Id. de secreto* |

Si la configuración falla, la herramienta dice exactamente qué revisar: tenant inexistente, client ID erróneo, secreto inválido o caducado, permisos delegados o falta de consentimiento.

### 3.3 Línea de comandos

```bash
python -m auditor                 # análisis completo + informe
python -m auditor --anonymize     # enmascara correos (a***@dominio.com) para compartir
```

El informe se guarda en `reports/permisos-<fecha>.{html,json,csv}`:
- **`.html`**: resumen, hallazgos por severidad y detalle con qué hacer.
- **`.json`**: completo, para integrarlo con otras herramientas.
- **`.csv`**: una fila por indicador u objeto afectado, para Excel o un sistema de incidencias.

### 3.4 Interfaz gráfica

```bash
python -m auditor.gui             # o: python -m auditor --gui   (admite --anonymize)
```

Ventana de escritorio hecha con **tkinter**, que viene con Python, así que no hay que instalar nada más. Analiza el tenant al abrirse, en segundo plano para que la ventana no se congele.

| Pestaña | Contenido |
|---|---|
| **Hallazgos** | Lista coloreada por severidad. Al seleccionar uno se ve su descripción, qué hacer y cada indicador con su peso. |
| **Permisos de la herramienta** | 🔴 Los que **no deberían estar** (escritura o contenido sensible) · 🟠 Los que sobran · 🟢 Los necesarios · ⚪ Delegados sin uso |
| **Matriz de acceso** | Los 21 endpoints probados, con las discrepancias resaltadas |

**Atajos:** `Ctrl+R` actualizar · `Ctrl+E` exportar informe · `Esc` cerrar.
En Linux, si falla `import tkinter`: `sudo apt install python3-tk`.

### 3.5 Tests

```bash
pytest
```

13 tests con datos de ejemplo. Cubren un consent phishing de manual (Crítica), una app legítima que no debe saltar, la exclusión de Microsoft y de la propia herramienta, una puerta trasera en una app de Microsoft y los falsos positivos encontrados en la ejecución real. **No necesitan tenant ni credenciales.**

---

## 4. Hallazgos en el tenant de pruebas

Ejecución del **18/11/2026**: 111 aplicaciones empresariales (100 de Microsoft, 11 propias, 0 de terceros) y 14 registros de aplicaciones.

> ✅ **No se han detectado concesiones fraudulentas de terceros.** Sí hay riesgos de configuración:

| Sev. | ID | Hallazgo | Detalle |
|:---:|---|---|---|
| 🟧 Alta | PRM-001 | La herramienta tiene 3 permisos de **escritura** | `AdministrativeUnitMember.ReadWrite.All`, `AgentIdUser.ReadWrite.All`, `AgentCard.ReadWrite.ManagedBy` |
| 🟧 Alta | PRM-002 | Permiso de lectura de contenido sensible | `AiEnterpriseInteraction.Read.All` permite leer los prompts y respuestas de Copilot de todos los usuarios |
| 🟨 Media | CON-MS2 | Herramientas de Microsoft con consentimientos delegados peligrosos | Graph Explorer: `Directory.ReadWrite.All`, `User.ReadWrite.All`. Graph CLI: `Mail.Read` |
| 🟨 Media | ACC-001 | Endpoint accesible sin el permiso documentado | `/organization` responde sin `Organization.Read.All` |
| 🟨 Media | ORG-001 | El tenant no tiene Entra ID P1/P2 | Sin acceso condicional para limitar quién consiente apps |
| 🟨 Media | APP-001 | Secreto a punto de caducar | Una app de auditoría (`tenant-audit-tool-a***`), el 30/11/2026 |
| 🟨 Media | APP-002 | Secreto con validez superior a 12 meses | `WazuhConnector2`: 24 meses |
| 🟦 Baja | ACC-002 | 4 permisos latentes sin licencia | Se activarían solos al contratar P1/P2 |
| 🟦 Baja | PRM-004 / 005 | 19 permisos innecesarios y 12 delegados sin uso | Mínimo privilegio |
| 🟦 Baja | APP-003 | 12 aplicaciones sin propietario | Nadie es responsable de sus secretos ni de sus permisos |
| 🟦 Baja | ORG-002 / 004 · GOV-001 | Sin contacto de seguridad ni de privacidad, sin revisiones de acceso | |

**Remediación prioritaria**
1. Quitar los permisos de escritura y `AiEnterpriseInteraction.Read.All` de la app.
2. Revocar los consentimientos de Graph Explorer y Graph CLI si ya no se usan.
3. Rotar el secreto que caduca y acortar el de 24 meses.
4. Asignar propietarios a las aplicaciones.

*He anonimizado los nombres de apps y secretos que contenían nombres de personas.*

---

## 5. Memoria

### 5.1 Del enunciado al producto

El enunciado proponía auditar usuarios, invitados, roles, MFA, inactividad y licencias con 5 permisos concretos. Construí esa versión primero, pero en el tenant de pruebas la app terminó con **24 permisos de aplicación distintos**, ninguno de los 5, y `/users` devolvía 403.

Como la prueba permitía experimentar, **cambié la pregunta en lugar de abandonarla**: *¿qué se puede averiguar con lo que hay?* Al explorar los endpoints uno a uno, sin datos personales, vi que `Application.Read.All` da acceso a todas las apps, a sus permisos y a los consentimientos de los usuarios. Con eso se responde una pregunta de seguridad muy relevante: **¿alguien ha metido en el tenant una app con permisos que no debería tener?**

Elegí el *consent phishing* como foco por tres motivos:
- **Se salta la contraseña y el MFA.** El token sigue funcionando aunque el usuario cambie la contraseña.
- **Es difícil de ver a mano.** Hay más de 100 apps empresariales, y los consentimientos de cada una no aparecen en una sola pantalla.
- **Necesita un solo permiso de lectura.**

```
Enunciado (5 hallazgos)  →  la app no tiene esos permisos (403)  →  explorar qué SÍ se puede leer
        →  Application.Read.All abre apps y consentimientos  →  detector de concesiones fraudulentas
        →  la primera ejecución real destapa falsos positivos  →  corregir y cubrir con tests  →  interfaz gráfica
```

### 5.2 Línea de pensamiento

1. **La pregunta.** *¿Hay alguna app con permisos que no debería tener, y la ha metido un atacante?*
2. **Puntuar indicadores en lugar de aplicar reglas sueltas.** "App de terceros" o "app nueva" por separado son normales; juntas y con acceso al correo no lo son. Una puntuación aditiva permite explicar cada alerta línea por línea y probar cada indicador con un test.
3. **Desconfiar del primer resultado.** La primera ejecución real marcó como Crítica una herramienta oficial de Microsoft. Antes de dar por bueno un hallazgo, me pregunto cuándo sería mentira (ver 5.4).
4. **Legítimo no significa inofensivo.** Graph Explorer es de Microsoft, pero si alguien le concede `Directory.ReadWrite.All` ese consentimiento persiste. Se reporta aparte, como riesgo y no como fraude.
5. **"No sé" no es lo mismo que "está bien".** La matriz de acceso distingue entre "no hay hallazgos" y "no he podido mirar". Un informe que dice "0 problemas" sin haber podido leer los datos es peligroso.
6. **La herramienta también se audita a sí misma.** Un detector de permisos excesivos con permisos excesivos no es creíble.
7. **Separar datos, lógica e informe.** Las reglas son **funciones puras**: reciben datos y devuelven hallazgos, así que se prueban sin tenant. La línea de comandos y la ventana comparten la misma función de análisis, por lo que siempre dan el mismo resultado.
8. **Mínimo privilegio.** Todo lo esencial sale de un único permiso de lectura.
9. **Herramientas sencillas y verificables.** Python con `msal` y `requests`, sin el SDK de Graph, para que cada llamada sea explícita y se pueda contrastar con Graph Explorer y Microsoft Learn. Interfaz con tkinter, sin dependencias nuevas.

### 5.3 Criterio de la puntuación

Los pesos reflejan **lo que un atacante necesita o lo que gana**:

- **+3**: lo que da mucho poder o es difícil de justificar en una app legítima. Imitar a Microsoft, permisos de alto impacto, credenciales añadidas a la app de un tercero.
- **+2**: lo que da acceso a datos o reduce la confianza. Permisos delegados sensibles, editor no verificado.
- **+1**: contexto que agrava. Tercero, consentimiento para toda la organización, `offline_access`, app reciente, URL `http://`.

Los umbrales se fijaron con casos reales:
- Un consent phishing de manual (tercero + no verificado + imita a Office + `Mail.Read` + `offline_access` + nuevo) suma **10**: Crítica.
- Una app propia con un permiso de escritura suma **3**: Media, legítima hasta que se demuestre lo contrario.
- Un tercero verificado con `openid` y `User.Read` suma **1** y no se reporta.

### 5.4 Falsos positivos

| Caso | Estado | Tratamiento |
|---|:---:|---|
| Herramientas de Microsoft alojadas en un tenant de Microsoft no listado (Graph Explorer, Graph CLI) | ✅ Corregido | Salían como **Crítica** en la ejecución real. Añadí el tenant `cdc5aeea-…`. Hay test. |
| App propia llamada "M365-…" o "Azure-…" | ✅ Corregido | La suplantación solo cuenta en apps de otros tenants. Hay test. |
| Apps nuevas en un tenant recién preparado | ✅ Mitigado | Solo suman +1: no disparan nada por sí solas. |
| Tercero verificado con permisos básicos | ✅ Mitigado | No se reporta. Hay test. |
| Tercero legítimo con "Office" o "Teams" en el nombre | ⚠️ Posible | Lo mitiga que el resto de indicadores también tiene que sumar. |
| Lista de tenants de Microsoft incompleta | ⚠️ Posible | Mejora: cruzar con la lista pública de *first-party apps*. |

### 5.5 Lo que revelaron los datos

- **La propia herramienta era el mayor riesgo.** Tenía 3 permisos de escritura y `AiEnterpriseInteraction.Read.All`, que permite leer las conversaciones de Copilot de todos los usuarios. Esos permisos los concedí yo al explorar, y la herramienta los detectó sin saber quién los había dado. En un caso real, una app de auditoría sobredimensionada, configurada por otra persona o heredada de una prueba anterior, es un riesgo habitual y fácil de pasar por alto. El `.env` se convierte en una credencial muy valiosa.
- **El acceso no coincide con los permisos.** `/organization` responde sin `Organization.Read.All`. Antes de conceder `Application.Read.All`, `/servicePrincipals` también respondía, probablemente por algún permiso de *Agent*. **Revisar una app solo por el nombre de sus permisos subestima lo que puede leer.**
- **Privilegio latente.** Hay 4 permisos concedidos (Identity Protection, Health Monitoring, Términos de uso) que hoy dan 403 por falta de licencia y que **se activarían solos** al contratar P1/P2.

### 5.6 Privacidad

- Los consentimientos delegados se resumen como "N usuarios", sin identificar a nadie.
- `--anonymize` enmascara los correos en el informe y en la interfaz.
- En este documento he enmascarado los nombres de apps y secretos que contenían nombres de personas.
- `.env` y `reports/` están en `.gitignore`. No se guardan tokens.

### 5.7 Errores de la IA y cómo los corregí

Usé Claude Code como andamiaje y **contrasté cada endpoint y cada permiso** con Microsoft Learn y con el propio Graph.

| # | Error | Cómo lo detecté | Corrección |
|:---:|---|---|---|
| 1 | Propuso `Reports.Read.All` para el informe de MFA | Contrastando con Microsoft Learn | El correcto es `AuditLog.Read.All` |
| 2 | El primer esqueleto pedía permisos fuera del enunciado y le faltaban áreas obligatorias | Al leer el enunciado | Rehecho sobre el alcance pedido |
| 3 | Supuso que todas las apps de Microsoft pertenecen a 2 tenants | La primera ejecución real marcó Graph CLI como **Crítica** | Añadido el tenant real, con test |
| 4 | Aplicaba "imita a Microsoft" también a las apps propias | Falso positivo con "M365-Audit-Dashboard" | Limitado a apps de otros tenants, con test |
| 5 | Solo leía los consentimientos de apps que no eran de Microsoft, así que la regla de Graph Explorer nunca podía dispararse | El hallazgo esperado no aparecía | Lectura ampliada a todas las apps |
| 6 | La interfaz actualizaba la ventana desde un hilo secundario, algo que tkinter no admite | Error `main thread is not in main loop` al probarla | Comunicación por cola, procesada desde el hilo principal |

### 5.8 Qué haría con más tiempo

- **Registro de auditoría** (`AuditLog.Read.All`): **quién** consintió cada app y **cuándo**, correlacionado con inicios de sesión de riesgo.
- **Lista oficial de apps de Microsoft** en lugar de una lista de tenants.
- **Política de consentimiento** (`Policy.Read.All`): comprobar si los usuarios pueden consentir apps sin aprobación de un administrador. Es la causa raíz que permite el consent phishing.
- **Comparar ejecuciones**: avisar solo de las concesiones **nuevas**, que es como lo usaría un SOC.
- **Generar una incidencia** por cada hallazgo Crítico o Alto en el registro del reto anterior. El CSV ya tiene IDs estables.
- **Autenticación con certificado** en lugar de secreto.

---

## 6. Arquitectura

Tres capas separadas, más la interfaz:

```
auditor/
├── config.py · auth.py · graph.py   # configuración, token (MSAL), cliente HTTP con paginación y reintentos
├── explore.py                       # DATOS: prueba endpoints, lee apps, permisos y consentimientos (analyze_tenant)
├── rules/                           # LÓGICA: funciones puras datos → hallazgos
│   ├── consent.py                   #   puntuación de concesiones sospechosas
│   └── exploration.py               #   permisos propios, acceso, registros de apps, organización, gobierno
├── report.py                        # INFORME: HTML / JSON / CSV, anonimización
├── gui.py                           # INTERFAZ: ventana tkinter
└── __main__.py                      # python -m auditor
tests/                               # test_consent.py · test_exploration.py
```

## 7. Seguridad de la propia herramienta

- 🔒 Solo hace peticiones `GET`: **no modifica nada** en el tenant.
- 🔒 `.env` (credenciales) y `reports/` (datos del tenant) están en `.gitignore`.
- 🔒 Se audita a sí misma y avisa si su app tiene más permisos de los necesarios.
