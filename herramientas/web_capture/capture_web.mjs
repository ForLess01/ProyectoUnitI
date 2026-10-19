import { mkdir, readFile, unlink, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright";

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const outputDirectory = path.resolve(scriptDirectory, "../../evidencias/web");
const indexPath = path.join(outputDirectory, "indice_web.json");
const viewport = { width: 1440, height: 1000 };
const deviceScaleFactor = 1.5;
const maxAttempts = 2;
const blockedAuthPatterns = [
  "*://*/*login*",
  "*://*/*signin*",
  "*://*/*sign-in*",
  "*://*/*auth*",
  "*://*/*oauth*",
  "*://*/*saml*",
];
const playwrightPackage = JSON.parse(
  await readFile(path.join(scriptDirectory, "node_modules/playwright/package.json"), "utf8"),
);

const targets = [
  {
    id: "WEB01",
    label: "Portal institucional",
    url: "https://portal.unap.edu.pe/",
  },
  {
    id: "WEB02",
    label: "Campus virtual",
    url: "https://campus.unap.edu.pe/",
  },
  {
    id: "WEB03",
    label: "Trámites institucionales",
    url: "https://tramites.unap.edu.pe/",
  },
  {
    id: "WEB04",
    label: "Aula virtual",
    url: "https://aulavirtual2.unap.edu.pe/",
  },
  {
    id: "WEB05",
    label: "Reglamento de Organización y Funciones",
    url: "https://portal.unap.edu.pe/documento/reglamento-de-organizacion-y-funciones",
  },
  {
    id: "WEB06",
    label: "Repositorio institucional",
    url: "https://portal.unap.edu.pe/repositorio-institucional",
  },
];

const utcNow = () => new Date().toISOString();
const officialHost = (hostname) =>
  hostname === "unap.edu.pe" || hostname.endsWith(".unap.edu.pe");
const authLikePath = (pathname) =>
  /(?:^|\/)(?:login|signin|sign-in|auth|oauth|saml)(?:\/|$)/i.test(pathname);

function safeUrl(rawUrl) {
  try {
    const url = new URL(rawUrl);
    url.search = "";
    url.hash = "";
    return url.href;
  } catch {
    return null;
  }
}

function safeError(error) {
  const message = `${error?.name ?? "Error"}: ${error?.message ?? String(error)}`;
  return message.replace(/https?:\/\/[^\s"'<>]+/g, (rawUrl) => safeUrl(rawUrl) ?? "[URL redacted]");
}

function makeInitialRecord(target) {
  return {
    id: target.id,
    label: target.label,
    requested_url: target.url,
    final_url: null,
    title: null,
    http_status: null,
    observed_at_utc: null,
    screenshot: null,
    state: "not_attempted",
    caption: null,
    demonstrates: null,
    does_not_demonstrate: null,
    official_logo_asset: null,
    attempts: [],
  };
}

async function saveIndex(records, browserInfo, runError = null) {
  const index = {
    generated_at_utc: utcNow(),
    browser: browserInfo,
    capture_settings: {
      viewport_css_pixels: viewport,
      device_scale_factor: deviceScaleFactor,
      screenshot_mode: "viewport",
      authenticated: false,
      interactions_performed: [],
      navigation_scope: "requested unap.edu.pe public pages only; auth-like URL patterns are blocked through Chrome Network and directly requested external documents through page routing",
    },
    run_error: runError,
    captures: records,
  };
  await writeFile(indexPath, `${JSON.stringify(index, null, 2)}\n`, "utf8");
}

async function getPageFacts(page) {
  return page.evaluate(() => {
    const viewportWidth = window.innerWidth;
    const viewportHeight = window.innerHeight;
    const visible = (element) => {
      const style = getComputedStyle(element);
      const rect = element.getBoundingClientRect();
      return (
        style.display !== "none" &&
        style.visibility !== "hidden" &&
        Number(style.opacity) !== 0 &&
        rect.width > 0 &&
        rect.height > 0 &&
        rect.right > 0 &&
        rect.bottom > 0 &&
        rect.left < viewportWidth &&
        rect.top < viewportHeight
      );
    };

    const bodyText = document.body?.innerText?.replace(/\s+/g, " ").trim() ?? "";
    const logoCandidates = [...document.images]
      .filter((image) => {
        const clue = `${image.alt} ${image.currentSrc} ${image.src}`;
        return /logo|escudo/i.test(clue) && image.naturalWidth > 0;
      })
      .map((image) => ({
        src: image.currentSrc || image.src,
        alt: image.alt,
        width: image.naturalWidth,
        height: image.naturalHeight,
        visible: visible(image),
      }))
      .slice(0, 12);

    return {
      title: document.title.trim(),
      body_text_length: bodyText.length,
      logo_candidates: logoCandidates,
    };
  });
}

async function downloadOfficialLogo(browserContext, logoCandidates) {
  const candidate = logoCandidates.find(
    (image) => image.visible && image.alt.trim() === "UNAP LOGO",
  );
  if (!candidate) {
    return {
      state: "not_found",
      reason: "No visible official-header image with alt text UNAP LOGO was found.",
    };
  }

  const source = new URL(candidate.src);
  const extension = source.pathname.toLowerCase().endsWith(".png")
    ? "png"
    : source.pathname.toLowerCase().endsWith(".svg")
      ? "svg"
      : null;
  if (
    source.hostname !== "portal.unap.edu.pe" ||
    !source.pathname.startsWith("/sites/default/files/") ||
    !extension
  ) {
    return {
      state: "not_downloaded",
      reason: "The logo candidate did not satisfy the official-host, public-file-path, and PNG/SVG checks.",
      source_url: safeUrl(source.href),
    };
  }

  try {
    const response = await browserContext.request.get(source.href, { timeout: 10_000 });
    const contentType = response.headers()["content-type"]?.split(";")[0].trim().toLowerCase() ?? null;
    const bytes = await response.body();
    const isPng =
      extension === "png" &&
      bytes.subarray(0, 8).equals(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]));
    const svgText = extension === "svg" ? bytes.toString("utf8").replace(/^\uFEFF?\s*/, "") : "";
    const isSvg = extension === "svg" && /^(?:<\?xml[^>]*>\s*)?<svg\b/i.test(svgText);

    if (response.status() !== 200 || !(isPng || isSvg)) {
      return {
        state: "not_downloaded",
        source_url: safeUrl(response.url()),
        http_status: response.status(),
        content_type: contentType,
        reason: "The official resource did not return a verified PNG/SVG image; no local asset was written.",
      };
    }

    const filename = `escudo_oficial.${extension}`;
    await writeFile(path.join(outputDirectory, filename), bytes);
    return {
      state: "downloaded_unaltered",
      filename,
      source_page: "https://portal.unap.edu.pe/",
      source_url: safeUrl(response.url()),
      http_status: response.status(),
      content_type: contentType,
      byte_length: bytes.length,
      sha256: createHash("sha256").update(bytes).digest("hex"),
      source_context:
        "The visible official portal header references this image with alt text UNAP LOGO; the file is served from portal.unap.edu.pe.",
      license_context:
        "No separate license statement was observed alongside the image on the inspected page. Official-site provenance is recorded; no additional reuse license is asserted. Original response bytes were kept unchanged.",
    };
  } catch (error) {
    return {
      state: "not_downloaded",
      source_url: safeUrl(source.href),
      reason: safeError(error),
    };
  }
}

async function captureTarget(browserContext, target) {
  const record = makeInitialRecord(target);
  const screenshotName = `${target.id}.png`;

  for (let attemptNumber = 1; attemptNumber <= maxAttempts; attemptNumber += 1) {
    const attempt = {
      attempt: attemptNumber,
      started_at_utc: utcNow(),
      final_url: null,
      http_status: null,
      error: null,
      blocked_navigations: [],
    };
    const page = await browserContext.newPage();
    const cdpSession = await browserContext.newCDPSession(page);
    await cdpSession.send("Network.enable");
    await cdpSession.send("Network.setBlockedURLs", { urls: blockedAuthPatterns });
    cdpSession.on("Network.requestWillBeSent", (event) => {
      if (event.type !== "Document") return;
      try {
        const destination = new URL(event.request.url);
        if (authLikePath(destination.pathname)) {
          const safeDestination = safeUrl(destination.href);
          if (safeDestination && !attempt.blocked_navigations.includes(safeDestination)) {
            attempt.blocked_navigations.push(safeDestination);
          }
        }
      } catch {
        // Ignore non-URL protocol events.
      }
    });
    let navigationResponse = null;

    page.on("response", (response) => {
      const request = response.request();
      if (request.isNavigationRequest() && request.frame() === page.mainFrame()) {
        navigationResponse = response;
      }
    });

    await page.route("**/*", async (route) => {
      const request = route.request();
      if (request.isNavigationRequest()) {
        const destination = new URL(request.url());
        if (!officialHost(destination.hostname) || authLikePath(destination.pathname)) {
          attempt.blocked_navigations.push(safeUrl(destination.href));
          await route.abort("blockedbyclient");
          return;
        }
      }
      await route.continue();
    });

    try {
      const response = await page.goto(target.url, {
        waitUntil: "domcontentloaded",
        timeout: 35_000,
      });
      navigationResponse = response ?? navigationResponse;
      attempt.http_status = navigationResponse?.status() ?? null;
      await page.locator("body").waitFor({ state: "visible", timeout: 10_000 });
      await page.waitForFunction(
        () => (document.body?.innerText?.trim().length ?? 0) > 20,
        { timeout: 10_000 },
      );
      await Promise.race([
        page.evaluate(() => document.fonts?.ready),
        page.waitForTimeout(2_000),
      ]);

      const facts = await getPageFacts(page);
      const status = navigationResponse?.status() ?? null;
      const finalUrl = page.url();
      attempt.final_url = finalUrl;
      attempt.http_status = status;

      if (!status || status < 200 || status >= 400) {
        throw new Error(`No se capturó imagen: respuesta HTTP ${status ?? "no disponible"}.`);
      }
      if (!officialHost(new URL(finalUrl).hostname) || authLikePath(new URL(finalUrl).pathname)) {
        throw new Error("No se capturó imagen: destino final fuera del alcance público permitido.");
      }

      await page.screenshot({
        path: path.join(outputDirectory, screenshotName),
        fullPage: false,
        type: "png",
      });

      record.final_url = finalUrl;
      record.title = facts.title || null;
      record.http_status = status;
      record.observed_at_utc = utcNow();
      record.screenshot = screenshotName;
      record.state = "captured";
      record.body_text_length = facts.body_text_length;
      record.logo_candidates = target.id === "WEB01" ? facts.logo_candidates : [];
      if (target.id === "WEB01") {
        record.official_logo_asset = await downloadOfficialLogo(browserContext, facts.logo_candidates);
      }
      record.caption = `${target.label}: vista pública de ${finalUrl} (título HTML: “${facts.title || "sin título"}”).`;
      record.demonstrates = `En ${record.observed_at_utc}, la URL final respondió HTTP ${status} y presentó esta vista pública sin iniciar sesión ni enviar formularios.`;
      record.does_not_demonstrate = "No acredita disponibilidad sostenida, controles de acceso internos, seguridad del servidor, ni funcionamiento de enlaces o formularios no utilizados.";
      attempt.final_url = finalUrl;
      attempt.completed_at_utc = record.observed_at_utc;
      record.attempts.push(attempt);
      await cdpSession.detach().catch(() => {});
      await page.close();
      return record;
    } catch (error) {
      attempt.final_url = safeUrl(page.url());
      attempt.http_status = navigationResponse?.status() ?? attempt.http_status;
      const redirectLocation = await navigationResponse?.headerValue("location").catch(() => null);
      if (redirectLocation) {
        try {
          const destination = new URL(redirectLocation, target.url);
          attempt.redirect_location = safeUrl(destination.href);
          if (authLikePath(destination.pathname) && !attempt.blocked_navigations.includes(attempt.redirect_location)) {
            attempt.blocked_navigations.push(attempt.redirect_location);
          }
        } catch {
          attempt.redirect_location = "[unparseable redirect location]";
        }
      }
      const blockedAuthRedirect = attempt.blocked_navigations.some((url) => {
        try {
          return authLikePath(new URL(url).pathname);
        } catch {
          return false;
        }
      });
      attempt.error = blockedAuthRedirect
        ? "Navigation stopped at an authentication/login redirect; no screenshot was captured."
        : safeError(error);
      attempt.completed_at_utc = utcNow();
      record.attempts.push(attempt);
      await unlink(path.join(outputDirectory, screenshotName)).catch(() => {});
      await cdpSession.detach().catch(() => {});
      await page.close().catch(() => {});

      if (attemptNumber === maxAttempts) {
        record.final_url = attempt.final_url || null;
        record.http_status = attempt.http_status;
        record.observed_at_utc = attempt.completed_at_utc;
        record.state = blockedAuthRedirect
          ? "blocked_auth_redirect_no_screenshot"
          : "failed_no_screenshot";
        record.caption = null;
        record.demonstrates = null;
        record.does_not_demonstrate = blockedAuthRedirect
          ? "No se generó imagen: el aula redirigió a una ruta de autenticación, que se bloqueó sin introducir credenciales ni enviar formularios."
          : "No se generó una imagen porque la navegación no se verificó correctamente; revisar el error y el estado HTTP registrados.";
      }
    }
  }

  return record;
}

async function main() {
  await mkdir(outputDirectory, { recursive: true });
  const records = targets.map(makeInitialRecord);
  let browser = null;
  let browserInfo = {
    automation: "Playwright for Node.js",
    playwright_version: playwrightPackage.version,
    launch_channel: "chrome",
    version: null,
  };

  try {
    browser = await chromium.launch({ channel: "chrome", headless: true });
    browserInfo.version = browser.version();
    const context = await browser.newContext({
      viewport,
      deviceScaleFactor,
      locale: "es-PE",
      timezoneId: "America/Lima",
      colorScheme: "light",
      acceptDownloads: false,
      serviceWorkers: "block",
    });

    for (let index = 0; index < targets.length; index += 1) {
      records[index] = await captureTarget(context, targets[index]);
      await saveIndex(records, browserInfo);
    }

    await context.close();
  } catch (error) {
    const runError = `${error?.name ?? "Error"}: ${error?.message ?? String(error)}`;
    for (const record of records) {
      if (record.state === "not_attempted") {
        record.state = "failed_no_screenshot";
        record.observed_at_utc = utcNow();
        record.does_not_demonstrate = "No se generó una imagen porque el navegador no pudo iniciar o la captura no se ejecutó.";
        record.attempts.push({ error: runError });
      }
    }
    await saveIndex(records, browserInfo, runError);
    process.exitCode = 1;
  } finally {
    await browser?.close().catch(() => {});
  }

  const failedCount = records.filter((record) => record.state !== "captured").length;
  if (failedCount > 0) process.exitCode = 1;
  process.stdout.write(
    `${JSON.stringify({
      index: indexPath,
      captured: records.filter((record) => record.state === "captured").length,
      failed: failedCount,
      browser: browserInfo,
    })}\n`,
  );
}

await main();
