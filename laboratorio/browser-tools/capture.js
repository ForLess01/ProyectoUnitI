#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const { spawn } = require("node:child_process");
const { chromium } = require("playwright-core");

const PROJECT_ROOT = path.resolve(__dirname, "../..");
const EVIDENCE_ROOT = path.join(PROJECT_ROOT, "evidencias", "laboratorio");
const DEFAULT_CAPTURE_DIR = path.join(EVIDENCE_ROOT, "capturas");
const PLAYWRIGHT_VERSION = require("playwright-core/package.json").version;
const CHROME_PATH = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
const DEMO_READER = {
  username: "lucia",
  password: "U7-lab-Reader!2026",
  totpSeedBase32: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
};

const TERMINAL_GROUPS = [
  { group: "auth_mfa", evidenceId: "TERM-01", cases: ["AUTH-01", "AUTH-02", "AUTH-03"], caption: "La consola PTY ejecutó los casos de credencial, MFA pendiente y MFA válido; el proceso terminó con estado 0." },
  { group: "rbac_idor", evidenceId: "TERM-02", cases: ["RBAC-01", "RBAC-02", "IDOR-01"], caption: "La consola PTY ejecutó denegación lector/admin, acceso admin autorizado y control de lectura A/B; el proceso terminó con estado 0." },
  { group: "integrity_audit", evidenceId: "TERM-03", cases: ["INT-01", "RBAC-03", "AUDIT-01"], caption: "La consola PTY ejecutó integridad, edición permitida por editor y validación de campos de auditoría; el proceso terminó con estado 0." },
  { group: "size_revocation", evidenceId: "TERM-04", cases: ["INPUT-01", "SESSION-01"], caption: "La consola PTY ejecutó el límite de 64 KiB, la solicitud posterior válida y la revocación efectiva; el proceso terminó con estado 0." },
  { group: "attack_backup", evidenceId: "TERM-05", cases: ["ATTACK-01", "RECOVERY-01"], caption: "La consola PTY ejecutó enumeración/copia/staging de fixtures con alerta y verificación de backup/restore SHA-256; el proceso terminó con estado 0." },
];

function parseArgs(argv) {
  const result = {
    baseUrl: "http://127.0.0.1:18765",
    terminalUrl: "http://127.0.0.1:18766",
    outputDir: DEFAULT_CAPTURE_DIR,
  };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--base-url") result.baseUrl = argv[++index];
    else if (argument === "--terminal-url") result.terminalUrl = argv[++index];
    else if (argument === "--output-dir") result.outputDir = argv[++index];
    else throw new Error(`Unsupported argument: ${argument}`);
  }
  return result;
}

function resolveCaptureDir(candidate) {
  const resolved = path.resolve(candidate);
  const requiredPrefix = `${DEFAULT_CAPTURE_DIR}${path.sep}`;
  if (resolved !== DEFAULT_CAPTURE_DIR && !resolved.startsWith(requiredPrefix)) {
    throw new Error(`Capture output must be below ${DEFAULT_CAPTURE_DIR}`);
  }
  return resolved;
}

function utcNow() {
  return new Date().toISOString();
}

function fixtureTotp(secretBase32, epochSeconds = Date.now() / 1000) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let accumulator = 0;
  let bitCount = 0;
  const decoded = [];
  for (const character of secretBase32.replace(/=+$/, "")) {
    const value = alphabet.indexOf(character);
    if (value < 0) throw new Error("Invalid local RFC 6238 fixture seed");
    accumulator = (accumulator << 5) | value;
    bitCount += 5;
    if (bitCount >= 8) {
      bitCount -= 8;
      decoded.push((accumulator >> bitCount) & 0xff);
    }
  }
  const counter = BigInt(Math.floor(epochSeconds / 30));
  const counterBytes = Buffer.alloc(8);
  counterBytes.writeBigUInt64BE(counter);
  const digest = crypto.createHmac("sha1", Buffer.from(decoded)).update(counterBytes).digest();
  const offset = digest[digest.length - 1] & 0x0f;
  const binary = digest.readUInt32BE(offset) & 0x7fffffff;
  return String(binary % 1_000_000).padStart(6, "0");
}

function validateLoopbackUrl(value, label) {
  const parsed = new URL(value);
  if (parsed.protocol !== "http:" || parsed.hostname !== "127.0.0.1") {
    throw new Error(`${label} must use explicit http://127.0.0.1 loopback`);
  }
  return parsed.origin;
}

async function waitForLocalServer(url, processHandle) {
  for (let attempt = 0; attempt < 60; attempt += 1) {
    if (processHandle && processHandle.exitCode !== null) {
      throw new Error(`PTY capture server exited with status ${processHandle.exitCode}`);
    }
    try {
      const response = await fetch(url, { signal: AbortSignal.timeout(700) });
      if (response.ok) return;
    } catch {
      // Retry only the explicitly local endpoint while the server starts.
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error(`Timed out waiting for loopback service ${url}`);
}

async function guardedContext(browser, allowedOrigin, viewport = { width: 1440, height: 980 }) {
  const context = await browser.newContext({
    viewport,
    deviceScaleFactor: 1,
    serviceWorkers: "block",
    acceptDownloads: false,
  });
  let blockedExternalRequests = 0;
  const requestedOrigins = new Set();
  await context.route("**/*", async (route) => {
    const requestUrl = new URL(route.request().url());
    if (requestUrl.origin !== allowedOrigin) {
      blockedExternalRequests += 1;
      await route.abort("blockedbyclient");
      return;
    }
    requestedOrigins.add(requestUrl.origin);
    await route.continue();
  });
  return { context, requestedOrigins, getBlockedExternalRequests: () => blockedExternalRequests };
}

async function saveScreenshot(page, outputPath) {
  const secretValues = await page.locator('input[type="password"], #totp-code').evaluateAll((inputs) => inputs.map((input) => input.value));
  assert(secretValues.every((value) => value === ""), "Password and TOTP inputs must be empty before capture");
  await page.screenshot({ path: outputPath, fullPage: true, animations: "disabled" });
  const stat = await fs.stat(outputPath);
  assert(stat.size > 10_000, "Expected a non-empty real browser screenshot");
  return { bytes: stat.size, capturedAtUtc: utcNow() };
}

async function captureTerminalGroups(browser, terminalOrigin, terminalUrl, captureDir, command) {
  const startedAt = utcNow();
  const started = performance.now();
  const guarded = await guardedContext(browser, terminalOrigin, { width: 1440, height: 980 });
  const page = await guarded.context.newPage();
  const evidence = [];
  const cases = [];
  try {
    await page.goto(terminalUrl, { waitUntil: "domcontentloaded", timeout: 10_000 });
    assert.match(await page.title(), /Consola PTY/);
    for (const item of TERMINAL_GROUPS) {
      await page.locator(`[data-group="${item.group}"]`).click();
      const startedPromise = page.waitForResponse(
        (response) => response.url() === `${terminalOrigin}/api/run/${item.group}` && response.status() === 202,
        { timeout: 10_000 },
      );
      await page.locator("#run").click();
      const startedResponse = await startedPromise;
      assert.equal(startedResponse.status(), 202);
      await page.waitForFunction(
        async (group) => {
          const response = await fetch(`/api/state/${group}`, { cache: "no-store" });
          if (!response.ok) return false;
          const state = await response.json();
          return state.status === "finished";
        },
        item.group,
        { timeout: 105_000, polling: 250 },
      );
      let state = null;
      for (let attempt = 0; attempt < 40; attempt += 1) {
        state = await page.evaluate(async () => {
          if (typeof poll !== "function") throw new Error("PTY terminal client poller is unavailable");
          return poll();
        });
        if (state && state.status === "finished") break;
        await page.waitForTimeout(100);
      }
      assert.equal(state?.status, "finished", `${item.group} PTY state must reach a terminal status`);
      assert.equal(await page.locator("#exit").innerText(), `exit status: ${state.exit_status}`);
      const casesPresent = item.cases.filter((caseId) => state.stdout.includes(caseId));
      const processOutputValid = state.output_bytes > 0 && /GROUP_RESULT/.test(state.stdout);
      const passed = state.exit_status === 0 && processOutputValid && casesPresent.length === item.cases.length;
      assert.match(await page.locator("#command").innerText(), /^docker exec /);
      assert.match(await page.locator("#exit").innerText(), new RegExp(`exit status: ${state.exit_status}`));

      const filename = `${item.evidenceId.toLowerCase()}-${item.group}.png`;
      const screenshotPath = path.join(captureDir, filename);
      const screenshot = await page.screenshot({ path: screenshotPath, fullPage: true, animations: "disabled" });
      assert.ok(screenshot.length > 10_000);
      evidence.push({
        evidence_id: item.evidenceId,
        case_ids: item.cases,
        path: path.relative(EVIDENCE_ROOT, screenshotPath),
        caption: passed
          ? item.caption
          : `La ejecución PTY del grupo ${item.group} terminó con estado ${state.exit_status}; la captura conserva la salida real observada.`,
        method: "playwright_page_screenshot_of_live_pty_terminal",
        source_origin: terminalOrigin,
        process_command: state.command,
        process_exit_status: state.exit_status,
        process_duration_ms: state.duration_ms,
        raw_log_path: `logs/terminal/${item.group}.log`,
        screenshot_bytes: screenshot.length,
        captured_at_utc: utcNow(),
      });
      cases.push({
        case_id: item.evidenceId,
        expected: "Allowlisted command ran through PTY and returned exit status 0 with the named test cases in stdout.",
        observed: {
          group: item.group,
        case_ids_in_stdout: casesPresent,
          exit_status: state.exit_status,
          output_bytes: state.output_bytes,
          duration_ms: state.duration_ms,
        },
        passed,
        command: state.command,
        started_utc: state.started_utc,
        duration_ms: state.duration_ms,
      });
    }
  } finally {
    await guarded.context.close();
  }
  assert.equal(guarded.getBlockedExternalRequests(), 0, "The PTY browser context must make no external requests");
  return {
    started_utc: startedAt,
    duration_ms: round(performance.now() - started),
    cases,
    evidence,
    metrics: {
      terminal_groups_executed: cases.length,
      process_exit_zero_count: cases.filter((item) => item.observed.exit_status === 0).length,
      blocked_external_requests: guarded.getBlockedExternalRequests(),
    },
    command,
  };
}

async function captureBrowserFlows(browser, baseOrigin, baseUrl, captureDir, command) {
  const startedAt = utcNow();
  const started = performance.now();
  const guarded = await guardedContext(browser, baseOrigin, { width: 1440, height: 980 });
  const page = await guarded.context.newPage();
  const cases = [];
  const evidence = [];
  const requestMetrics = { app_requests: 0, api_requests: 0, request_payload_bytes: 0, status_codes: {} };
  page.on("request", (request) => {
    const requestUrl = new URL(request.url());
    if (requestUrl.origin !== baseOrigin) return;
    requestMetrics.app_requests += 1;
    if (requestUrl.pathname.startsWith("/api/")) requestMetrics.api_requests += 1;
    requestMetrics.request_payload_bytes += request.postDataBuffer()?.length || 0;
  });
  page.on("response", (response) => {
    const responseUrl = new URL(response.url());
    if (responseUrl.origin !== baseOrigin) return;
    const status = String(response.status());
    requestMetrics.status_codes[status] = (requestMetrics.status_codes[status] || 0) + 1;
  });
  try {
    await page.goto(baseUrl, { waitUntil: "domcontentloaded", timeout: 10_000 });
    assert.match(await page.title(), /Acceso MFA/);
    assert.equal(await page.locator("#login-form").isVisible(), true);

    const loginStartedUtc = utcNow();
    const loginStarted = performance.now();
    await page.locator("#username").fill(DEMO_READER.username);
    await page.locator("#password").fill(DEMO_READER.password);
    const loginResponsePromise = page.waitForResponse(
      (response) => response.url() === `${baseOrigin}/api/login`,
      { timeout: 10_000 },
    );
    await page.locator("#login-button").click();
    const loginResponse = await loginResponsePromise;
    const loginBody = await loginResponse.json();
    assert.equal(loginResponse.status(), 401);
    assert.equal(loginBody.code, "mfa_required");
    assert.equal(loginBody.access_granted, false);
    assert.equal(await page.locator("#mfa-panel").isVisible(), true);
    assert.match(await page.locator("#status").innerText(), /HTTP 401.*MFA requerido/);
    const mfaCapture = await saveScreenshot(page, path.join(captureDir, "browser-01-mfa-required.png"));
    evidence.push({
      evidence_id: "BROWSER-01",
      case_ids: ["AUTH-02"],
      path: "capturas/browser-01-mfa-required.png",
      caption: "La contraseña correcta produjo HTTP 401 y exigió MFA; la interfaz indica que aún no se concedió acceso.",
      method: "playwright_page_screenshot_live_chromium",
      source_origin: baseOrigin,
      screenshot_bytes: mfaCapture.bytes,
      captured_at_utc: mfaCapture.capturedAtUtc,
    });
    cases.push({
      case_id: "BROWSER-01",
      expected: "Password-only login returns HTTP 401 and keeps the session unauthenticated.",
      observed: { status: loginResponse.status(), code: loginBody.code, access_granted: loginBody.access_granted },
      passed: true,
      command,
      started_utc: loginStartedUtc,
      duration_ms: round(performance.now() - loginStarted),
    });

    const mfaStartedUtc = utcNow();
    const mfaStarted = performance.now();
    await page.locator("#totp-code").fill(fixtureTotp(DEMO_READER.totpSeedBase32));
    const mfaResponsePromise = page.waitForResponse(
      (response) => response.url() === `${baseOrigin}/api/mfa`,
      { timeout: 10_000 },
    );
    await page.locator("#mfa-button").click();
    const mfaResponse = await mfaResponsePromise;
    const mfaBody = await mfaResponse.json();
    assert.equal(mfaResponse.status(), 200);
    assert.equal(mfaBody.status, "authenticated");
    assert.equal(mfaBody.user.role, "reader");
    await page.locator("#dashboard").waitFor({ state: "visible", timeout: 5_000 });
    await page.waitForFunction(() => document.querySelector("#record-content").textContent.includes("fictional laboratory data"));
    assert.match(await page.locator("#status").innerText(), /HTTP 200.*acceso permitido/);
    const accessCapture = await saveScreenshot(page, path.join(captureDir, "browser-02-access-allowed.png"));
    evidence.push({
      evidence_id: "BROWSER-02",
      case_ids: ["AUTH-03"],
      path: "capturas/browser-02-access-allowed.png",
      caption: "El TOTP válido permitió la sesión del rol lector y la lectura del registro ficticio A.",
      method: "playwright_page_screenshot_live_chromium",
      source_origin: baseOrigin,
      screenshot_bytes: accessCapture.bytes,
      captured_at_utc: accessCapture.capturedAtUtc,
    });
    cases.push({
      case_id: "BROWSER-02",
      expected: "Valid RFC 6238 TOTP creates an authenticated reader session and allows its fixture object.",
      observed: { status: mfaResponse.status(), role: mfaBody.user.role, fixture_visible: true },
      passed: true,
      command,
      started_utc: mfaStartedUtc,
      duration_ms: round(performance.now() - mfaStarted),
    });

    const rbacStartedUtc = utcNow();
    const rbacStarted = performance.now();
    const adminResponsePromise = page.waitForResponse(
      (response) => response.url() === `${baseOrigin}/api/admin`,
      { timeout: 10_000 },
    );
    await page.locator("#admin-button").click();
    const adminResponse = await adminResponsePromise;
    const adminBody = await adminResponse.json();
    assert.equal(adminResponse.status(), 403);
    assert.equal(adminBody.code, "forbidden");
    assert.match(await page.locator("#status").innerText(), /HTTP 403.*Acceso denegado/);
    const forbiddenCapture = await saveScreenshot(page, path.join(captureDir, "browser-03-rbac-403.png"));
    evidence.push({
      evidence_id: "BROWSER-03",
      case_ids: ["RBAC-01"],
      path: "capturas/browser-03-rbac-403.png",
      caption: "La solicitud al panel administrativo del rol lector recibió HTTP 403.",
      method: "playwright_page_screenshot_live_chromium",
      source_origin: baseOrigin,
      screenshot_bytes: forbiddenCapture.bytes,
      captured_at_utc: forbiddenCapture.capturedAtUtc,
    });
    cases.push({
      case_id: "BROWSER-03",
      expected: "Reader role is denied the administrative panel with HTTP 403.",
      observed: { status: adminResponse.status(), code: adminBody.code },
      passed: true,
      command,
      started_utc: rbacStartedUtc,
      duration_ms: round(performance.now() - rbacStarted),
    });

    const revokeStartedUtc = utcNow();
    const revokeStarted = performance.now();
    const revokeResponsePromise = page.waitForResponse(
      (response) => response.url() === `${baseOrigin}/api/session/revoke`,
      { timeout: 10_000 },
    );
    const sessionCheckPromise = page.waitForResponse(
      (response) => response.url() === `${baseOrigin}/api/me` && response.status() === 401,
      { timeout: 10_000 },
    );
    await page.locator("#revoke-button").click();
    const [revokeResponse, sessionCheck] = await Promise.all([revokeResponsePromise, sessionCheckPromise]);
    assert.equal(revokeResponse.status(), 200);
    assert.equal(sessionCheck.status(), 401);
    assert.match(await page.locator("#status").innerText(), /HTTP 401.*Sesión revocada/);
    assert.equal(await page.locator("#revoke-button").isDisabled(), true);
    const revokeCapture = await saveScreenshot(page, path.join(captureDir, "browser-04-session-revoked.png"));
    evidence.push({
      evidence_id: "BROWSER-04",
      case_ids: ["SESSION-01"],
      path: "capturas/browser-04-session-revoked.png",
      caption: "Después de revocar la sesión, la siguiente solicitud recibió HTTP 401.",
      method: "playwright_page_screenshot_live_chromium",
      source_origin: baseOrigin,
      screenshot_bytes: revokeCapture.bytes,
      captured_at_utc: revokeCapture.capturedAtUtc,
    });
    cases.push({
      case_id: "BROWSER-04",
      expected: "Session revocation returns HTTP 200 and the next session check is denied with HTTP 401.",
      observed: { revoke_status: revokeResponse.status(), follow_up_status: sessionCheck.status() },
      passed: true,
      command,
      started_utc: revokeStartedUtc,
      duration_ms: round(performance.now() - revokeStarted),
    });
  } finally {
    await guarded.context.close();
  }
  assert.equal(guarded.getBlockedExternalRequests(), 0, "The app browser context must make no external requests");
  assert.ok(guarded.requestedOrigins.size === 1 && guarded.requestedOrigins.has(baseOrigin));
  return {
    started_utc: startedAt,
    duration_ms: round(performance.now() - started),
    cases,
    evidence,
    metrics: {
      browser_cases_passed: cases.filter((item) => item.passed).length,
      ...requestMetrics,
      local_origins_seen: [...guarded.requestedOrigins],
      blocked_external_requests: guarded.getBlockedExternalRequests(),
    },
    command,
  };
}

function round(value) {
  return Number(value.toFixed(3));
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const captureDir = resolveCaptureDir(args.outputDir);
  const baseOrigin = validateLoopbackUrl(args.baseUrl, "--base-url");
  const terminalOrigin = validateLoopbackUrl(args.terminalUrl, "--terminal-url");
  if (baseOrigin === terminalOrigin) throw new Error("App and PTY terminal must use distinct explicit loopback ports");
  if (!(await fs.stat(CHROME_PATH).catch(() => null))) throw new Error(`Chrome executable not found at ${CHROME_PATH}`);
  await fs.mkdir(captureDir, { recursive: true });
  await fs.mkdir(path.join(EVIDENCE_ROOT, "work", "capture-home"), { recursive: true });
  await fs.mkdir(path.join(EVIDENCE_ROOT, "work", "capture-tmp"), { recursive: true });

  const command = `node laboratorio/browser-tools/capture.js --base-url ${args.baseUrl} --terminal-url ${args.terminalUrl} --output-dir ${path.relative(PROJECT_ROOT, captureDir)}`;
  const terminalServerArgs = [
    path.join(PROJECT_ROOT, "herramientas", "lab_capture.py"),
    "--serve",
    "--container",
    "proyectouniti-lab-demo",
    "--port",
    "18766",
    "--proxy-port",
    "18765",
    "--evidence-dir",
    EVIDENCE_ROOT,
  ];
  const helperEnvironment = {
    PATH: process.env.PATH || "/usr/local/bin:/usr/bin:/bin",
    HOME: process.env.HOME || path.join(EVIDENCE_ROOT, "work", "capture-home"),
    TMPDIR: path.join(EVIDENCE_ROOT, "work", "capture-tmp"),
    LANG: "C.UTF-8",
    LC_ALL: "C.UTF-8",
    TZ: "UTC",
  };
  for (const name of ["DOCKER_CONFIG", "DOCKER_HOST", "DOCKER_CONTEXT"]) {
    if (process.env[name]) helperEnvironment[name] = process.env[name];
  }
  const terminalServer = spawn("python3", terminalServerArgs, {
    cwd: PROJECT_ROOT,
    env: helperEnvironment,
    stdio: "ignore",
  });
  let browser;
  const startedAt = utcNow();
  try {
    await waitForLocalServer(args.terminalUrl, terminalServer);
    await waitForLocalServer(args.baseUrl, terminalServer);
    const cleanBrowserEnvironment = {
      PATH: process.env.PATH || "/usr/local/bin:/usr/bin:/bin",
      HOME: path.join(EVIDENCE_ROOT, "work", "capture-home"),
      TMPDIR: path.join(EVIDENCE_ROOT, "work", "capture-tmp"),
      LANG: "C.UTF-8",
      LC_ALL: "C.UTF-8",
      TZ: "UTC",
    };
    browser = await chromium.launch({
      executablePath: CHROME_PATH,
      headless: false,
      timeout: 20_000,
      env: cleanBrowserEnvironment,
      args: [
        "--no-first-run",
        "--disable-background-networking",
        "--disable-component-update",
        "--disable-default-apps",
        "--disable-domain-reliability",
        "--disable-sync",
        "--disable-extensions",
        "--disable-features=MediaRouter",
      ],
    });
    const browserVersion = browser.version();
    const terminalResults = await captureTerminalGroups(browser, terminalOrigin, args.terminalUrl, captureDir, command);
    const browserResults = await captureBrowserFlows(browser, baseOrigin, args.baseUrl, captureDir, command);
    const output = {
      started_utc: startedAt,
      finished_utc: utcNow(),
      command,
      stack: {
        node: process.version,
        playwright_core: PLAYWRIGHT_VERSION,
        host_platform: `${os.platform()} ${os.arch()} ${os.release()}`,
        browser: "Google Chrome",
        browser_version: browserVersion,
        executable: CHROME_PATH,
        headless: false,
      },
      terminal: terminalResults,
      browser: browserResults,
      evidence: [...terminalResults.evidence, ...browserResults.evidence],
      cases: [...terminalResults.cases, ...browserResults.cases],
    };
    const resultPath = path.join(EVIDENCE_ROOT, "browser-results.json");
    await fs.writeFile(resultPath, `${JSON.stringify(output, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
    const outputLines = [
      `BROWSER_CAPTURE_RESULT cases=${output.cases.filter((item) => item.passed).length}/${output.cases.length} terminal=${terminalResults.metrics.terminal_groups_executed}/5 browser=${browserResults.metrics.browser_cases_passed}/4 screenshots=${output.evidence.length}`,
      `BROWSER_CAPTURE_JSON ${path.relative(PROJECT_ROOT, resultPath)}`,
      ...output.evidence.map((item) => `SCREENSHOT ${item.evidence_id} ${item.path} ${item.method}`),
    ];
    const browserLog = path.join(EVIDENCE_ROOT, "logs", "browser_capture.log");
    await fs.mkdir(path.dirname(browserLog), { recursive: true });
    await fs.writeFile(browserLog, `${outputLines.join("\n")}\n`, { encoding: "utf8", mode: 0o600 });
    for (const line of outputLines) process.stdout.write(`${line}\n`);
    if (output.cases.some((item) => !item.passed)) process.exitCode = 1;
  } finally {
    if (browser) await browser.close();
    terminalServer.kill("SIGTERM");
    await new Promise((resolve) => {
      if (terminalServer.exitCode !== null) resolve();
      else {
        terminalServer.once("exit", resolve);
        setTimeout(resolve, 2_000);
      }
    });
    await fs.rm(path.join(EVIDENCE_ROOT, "work", "capture-home"), { recursive: true, force: true });
    await fs.rm(path.join(EVIDENCE_ROOT, "work", "capture-tmp"), { recursive: true, force: true });
  }
}

main().catch((error) => {
  const message = `BROWSER_CAPTURE_FAILED ${error.name}: ${error.message}`;
  const browserLog = path.join(EVIDENCE_ROOT, "logs", "browser_capture.log");
  fs.mkdir(path.dirname(browserLog), { recursive: true })
    .then(() => fs.appendFile(browserLog, `${message}\n`, { encoding: "utf8", mode: 0o600 }))
    .catch(() => {});
  console.error(message);
  process.exitCode = 1;
});
