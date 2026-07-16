/* ─────────────────────────────────────────────────────────────
   IcebergEBS · Risk-trend chart renderer  (CSP-safe, external file)
   Loaded via {% block page_js %} on the extension detail page —
   inline scripts are blocked by the strict CSP (#106).

   Markup it expects:

     <div id="risk-trend"></div>
     <div id="risk-trend-mini"></div>   (optional compact version)
     <script type="application/json" id="score-history">
       {"points": [{"d":"May 11","s":41}, …],
        "bands":  [{"band":"low","from":0,"to":25}, …]}
     </script>

   The payload is built by routes/ui.py:extension_detail. `points` come from
   FetchLog rows; `bands` is the score→band geometry derived server-side from
   extension_queries.RISK_BANDS (which mirrors scoring.risk_level — the single
   home of the 75/50/25 thresholds). This file must NOT re-inline those cut
   points: line/dot/shading colours and grid lines are all driven by the
   payload, and the colours resolve through app.css's --risk-* tokens so the
   chart follows the light/dark theme (#105).
   ───────────────────────────────────────────────────────────── */

(function () {
  let bands = []; // [{band, from, to}] from the server payload, sorted by `from`

  // The SVG is assembled as an HTML string, so every non-numeric value that
  // reaches it must be escaped (CodeQL js/xss-through-dom: the island payload
  // is DOM text and must not be reinterpreted as HTML). Numbers are coerced
  // via toFixed()/Number() at their interpolation sites.
  function esc(value) {
    return String(value)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function riskToken(band) {
    return esc(getComputedStyle(document.documentElement).getPropertyValue('--risk-' + band).trim());
  }

  function bandFor(score) {
    for (let i = bands.length - 1; i >= 0; i--) {
      if (score >= bands[i].from) return bands[i].band;
    }
    return bands.length ? bands[0].band : 'unknown';
  }

  function bandColor(score) {
    return riskToken(bandFor(score));
  }

  function renderTrend(container, data, opts) {
    const axis = !!opts.axis;
    const W = 900, H = opts.height, padL = axis ? 34 : 8, padR = 8, padT = 12, padB = axis ? 22 : 8;
    const plotW = W - padL - padR, plotH = H - padT - padB;
    if (!data.length) { container.innerHTML = ''; return; }
    const x = i => padL + (data.length === 1 ? plotW / 2 : (i / (data.length - 1)) * plotW);
    const y = s => padT + (1 - s / 100) * plotH;

    const linePts = data.map((d, i) => x(i).toFixed(1) + ',' + y(d.s).toFixed(1)).join(' ');
    const areaPath = 'M ' + x(0).toFixed(1) + ',' + (padT + plotH).toFixed(1) + ' L ' +
      data.map((d, i) => x(i).toFixed(1) + ',' + y(d.s).toFixed(1)).join(' L ') +
      ' L ' + x(data.length - 1).toFixed(1) + ',' + (padT + plotH).toFixed(1) + ' Z';

    const cur = data[data.length - 1].s;
    const stroke = bandColor(cur);

    const bandRects = bands.map(b => {
      const y1 = y(b.to), y2 = y(b.from);
      return '<rect class="band" x="' + padL + '" y="' + y1.toFixed(1) + '" width="' + plotW + '" height="' + (y2 - y1).toFixed(1) + '" fill="' + riskToken(b.band) + '"></rect>';
    }).join('');

    // Interior band boundaries (every `from` except the bottom of the scale).
    const boundaries = bands.map(b => b.from).filter(v => v > 0);
    const gridLines = axis ? boundaries.map(v =>
      '<line class="grid-line" x1="' + padL + '" y1="' + y(v).toFixed(1) + '" x2="' + (W - padR) + '" y2="' + y(v).toFixed(1) + '"></line>' +
      '<text class="axis-label" x="6" y="' + (y(v) + 3).toFixed(1) + '">' + v + '</text>').join('') : '';

    const dots = axis ? data.map((d, i) =>
      '<circle class="dot" cx="' + x(i).toFixed(1) + '" cy="' + y(d.s).toFixed(1) + '" r="3" fill="' + bandColor(d.s) + '"></circle>').join('') : '';

    const xLabels = axis ?
      '<text class="axis-label" x="' + padL + '" y="' + (H - 6) + '" text-anchor="start">' + esc(data[0].d) + '</text>' +
      '<text class="axis-label" x="' + (W - padR) + '" y="' + (H - 6) + '" text-anchor="end">' + esc(data[data.length - 1].d) + '</text>' : '';

    const cx = x(data.length - 1), cy = y(cur);
    const marker = '<circle cx="' + cx.toFixed(1) + '" cy="' + cy.toFixed(1) + '" r="' + (axis ? 4.5 : 3.5) + '" fill="' + stroke + '" stroke="var(--surface)" stroke-width="2"></circle>';

    container.innerHTML =
      '<svg class="trend" viewBox="0 0 ' + W + ' ' + H + '" preserveAspectRatio="none" width="100%" height="' + H + '">' +
      bandRects + gridLines +
      '<path class="area" d="' + areaPath + '" fill="' + stroke + '" fill-opacity="0.12"></path>' +
      '<polyline class="line" points="' + linePts + '" stroke="' + stroke + '"></polyline>' +
      dots + marker + xLabels +
      '</svg>';
  }

  document.addEventListener('DOMContentLoaded', function () {
    const island = document.getElementById('score-history');
    if (!island) return;
    let payload = null;
    try { payload = JSON.parse(island.textContent || 'null'); } catch (e) { return; }
    if (!payload || !Array.isArray(payload.points) || !Array.isArray(payload.bands)) return;
    // Allowlist-validate the payload shape: band names must be plain lowercase
    // words (they become CSS custom-property lookups) and the geometry numeric.
    const data = payload.points.filter(p => typeof p.s === 'number' && Number.isFinite(p.s));
    bands = payload.bands
      .filter(b => typeof b.band === 'string' && /^[a-z]+$/.test(b.band)
        && typeof b.from === 'number' && typeof b.to === 'number')
      .sort((a, b) => a.from - b.from);
    if (!bands.length) return;
    const full = document.getElementById('risk-trend');
    const mini = document.getElementById('risk-trend-mini');
    function render() {
      if (full) renderTrend(full, data, { height: 220, axis: true });
      if (mini) renderTrend(mini, data, { height: 90, axis: false });
    }
    render();
    // The SVG bakes resolved token values into fill/stroke attributes, so
    // re-render when the theme picker flips html[data-theme].
    new MutationObserver(render).observe(document.documentElement, {
      attributes: true,
      attributeFilter: ['data-theme'],
    });
  });
})();
