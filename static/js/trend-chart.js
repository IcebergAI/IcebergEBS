/* ─────────────────────────────────────────────────────────────
   IcebergEBS · Risk-trend chart renderer  (CSP-safe, external file)
   Drop into  static/js/trend-chart.js  and load with:
     <script src="/static/js/trend-chart.js"></script>
   (Inline scripts are blocked by the CSP — see CLAUDE.md — so this
    must be an external file, not an inline <script>.)

   Markup it expects on the extension detail page:

     <div id="risk-trend"></div>
     <div id="risk-trend-mini"></div>   (optional compact version)
     <script type="application/json" id="score-history">
       [{"d":"May 11","s":41},{"d":"May 29","s":68}]   {# from FetchLog #}
     </script>

   Build the JSON island in ui.py / the template from FetchLog rows:
     history = [
       {"d": log.fetched_at.strftime("%b %d"), "s": log.risk_score_after}
       for log in reversed(fetch_logs)
       if log.success and log.risk_score_after is not None
     ]
   …then  {{ history | tojson }}  inside the <script type="application/json">.
   ───────────────────────────────────────────────────────────── */

(function () {
  // Band colours come from app.css's --risk-* tokens (#105) so the SVG follows
  // the light/dark theme — never hard-code an oklch literal here. The 25/50/75
  // cut points mirror app/scoring.risk_level (the single home of the score
  // thresholds); the chart re-renders on theme change via the observer below.
  function riskToken(band) {
    return getComputedStyle(document.documentElement).getPropertyValue('--risk-' + band).trim();
  }

  function bandColor(pct) {
    return riskToken(pct >= 75 ? 'critical' : pct >= 50 ? 'high' : pct >= 25 ? 'medium' : 'low');
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

    const bands = [
      { from: 0, to: 25, c: riskToken('low') },
      { from: 25, to: 50, c: riskToken('medium') },
      { from: 50, to: 75, c: riskToken('high') },
      { from: 75, to: 100, c: riskToken('critical') },
    ].map(b => {
      const y1 = y(b.to), y2 = y(b.from);
      return '<rect class="band" x="' + padL + '" y="' + y1.toFixed(1) + '" width="' + plotW + '" height="' + (y2 - y1).toFixed(1) + '" fill="' + b.c + '"></rect>';
    }).join('');

    const gridLines = axis ? [25, 50, 75].map(v =>
      '<line class="grid-line" x1="' + padL + '" y1="' + y(v).toFixed(1) + '" x2="' + (W - padR) + '" y2="' + y(v).toFixed(1) + '"></line>' +
      '<text class="axis-label" x="6" y="' + (y(v) + 3).toFixed(1) + '">' + v + '</text>').join('') : '';

    const dots = axis ? data.map((d, i) =>
      '<circle class="dot" cx="' + x(i).toFixed(1) + '" cy="' + y(d.s).toFixed(1) + '" r="3" fill="' + bandColor(d.s) + '"></circle>').join('') : '';

    const xLabels = axis ?
      '<text class="axis-label" x="' + padL + '" y="' + (H - 6) + '" text-anchor="start">' + data[0].d + '</text>' +
      '<text class="axis-label" x="' + (W - padR) + '" y="' + (H - 6) + '" text-anchor="end">' + data[data.length - 1].d + '</text>' : '';

    const cx = x(data.length - 1), cy = y(cur);
    const marker = '<circle cx="' + cx.toFixed(1) + '" cy="' + cy.toFixed(1) + '" r="' + (axis ? 4.5 : 3.5) + '" fill="' + stroke + '" stroke="var(--surface)" stroke-width="2"></circle>';

    container.innerHTML =
      '<svg class="trend" viewBox="0 0 ' + W + ' ' + H + '" preserveAspectRatio="none" width="100%" height="' + H + '">' +
      bands + gridLines +
      '<path class="area" d="' + areaPath + '" fill="' + stroke + '" fill-opacity="0.12"></path>' +
      '<polyline class="line" points="' + linePts + '" stroke="' + stroke + '"></polyline>' +
      dots + marker + xLabels +
      '</svg>';
  }

  document.addEventListener('DOMContentLoaded', function () {
    const island = document.getElementById('score-history');
    if (!island) return;
    let data = [];
    try { data = JSON.parse(island.textContent || '[]'); } catch (e) { return; }
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
