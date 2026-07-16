// <paytp-demos> — the whole demo suite as one inline custom element.
//
// Drop `<paytp-demos></paytp-demos>` into any page and it renders the suite in the
// normal document flow (the page scrolls, not a nested iframe), with its styles
// isolated in a shadow root so they neither leak out nor get clobbered by the host.
// The host site provides the header/nav/footer; this element is just the demo body.
//
// Usage on a site page:
//   <script type="module" src="demos/paytp-demos.js"></script>
//   <paytp-demos></paytp-demos>
//
// Theme: follows the host document's data-theme (the site's light/dark toggle) with a
// prefers-color-scheme fallback; a `theme="dark|light"` attribute pins it explicitly.
import { mount } from "./app.js";

// Resolve sibling assets (style.css) relative to THIS module, not the host page —
// the site embedding us can live at any path.
const BASE = new URL(".", import.meta.url).href;

// The demo body: nav + stage only. No page chrome (header/footer/theme toggle) —
// the host site owns that. Element ids match what app.js queries via $.
const TEMPLATE = `
<div class="layout">
  <nav id="nav" class="nav" aria-label="Demos"></nav>
  <main class="stage">
    <div id="engine-status" class="status" role="status">Loading the PayTP core (WASM)…</div>
    <section id="demo" class="demo" hidden>
      <div class="demo-head">
        <h2 id="demo-title"></h2>
        <p id="demo-proves" class="proves"></p>
        <div class="controls">
          <span id="demo-tier" class="tag"></span>
          <div id="demo-inputs" class="inputs"></div>
          <button id="run" class="run">Run &#9656;</button>
        </div>
      </div>
      <div id="viz" class="viz" aria-live="polite"></div>
      <details id="hood" class="hood">
        <summary>Under the hood &mdash; the wire facts</summary>
        <div id="hood-note" class="hood-note"></div>
        <pre id="hood-trace" class="trace"></pre>
      </details>
    </section>
  </main>
</div>`;

class PaytpDemos extends HTMLElement {
  async connectedCallback() {
    if (this._mounted) return; // custom elements can re-connect; mount once
    this._mounted = true;

    const root = this.attachShadow({ mode: "open" });
    root.innerHTML = `<link rel="stylesheet" href="${BASE}style.css">${TEMPLATE}`;

    this._syncTheme();
    // Follow the site's theme toggle (data-theme on <html>) live.
    this._obs = new MutationObserver(() => this._syncTheme());
    this._obs.observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });

    await mount(root, { themeEl: this });
  }

  disconnectedCallback() { this._obs?.disconnect(); }

  // Explicit attribute wins; else mirror the host document's data-theme; else leave
  // unset so the shadow CSS falls back to prefers-color-scheme.
  _syncTheme() {
    const pinned = this.getAttribute("theme");
    const t = pinned || document.documentElement.getAttribute("data-theme");
    if (t === "dark" || t === "light") this.setAttribute("data-theme", t);
    else this.removeAttribute("data-theme");
  }
}

customElements.define("paytp-demos", PaytpDemos);
