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
   points, and colours resolve through app.css's --risk-* tokens so the chart
   follows the light/dark theme (#105).

   The SVG is constructed with DOM APIs (createElementNS / setAttribute /
   textContent), never innerHTML — the island payload is DOM text and must not
   be reinterpreted as HTML (CodeQL js/xss-through-dom).
   ───────────────────────────────────────────────────────────── */

(function () {
  const SVG_NS = 'http://www.w3.org/2000/svg';

  let bands = []; // [{band, from, to}] from the server payload, sorted by `from`

  function el(name, attrs, text) {
    const node = document.createElementNS(SVG_NS, name);
    for (const key in attrs) node.setAttribute(key, attrs[key]);
    if (text != null) node.textContent = text;
    return node;
  }

  function riskToken(band) {
    return getComputedStyle(document.documentElement).getPropertyValue('--risk-' + band).trim();
  }

  function bandFor(score) {
    for (let i = bands.length - 1; i >= 0; i--) {
      if (score >= bands[i].from) return bands[i].band;
    }
    return bands[0].band;
  }

  function bandColor(score) {
    return riskToken(bandFor(score));
  }

  function renderTrend(container, data, opts) {
    const axis = !!opts.axis;
    const W = 900, H = opts.height, padL = axis ? 34 : 8, padR = 8, padT = 12, padB = axis ? 22 : 8;
    const plotW = W - padL - padR, plotH = H - padT - padB;
    if (!data.length) { container.replaceChildren(); return; }
    const x = i => padL + (data.length === 1 ? plotW / 2 : (i / (data.length - 1)) * plotW);
    const y = s => padT + (1 - s / 100) * plotH;

    const svg = el('svg', {
      class: 'trend', viewBox: '0 0 ' + W + ' ' + H,
      preserveAspectRatio: 'none', width: '100%', height: H,
    });

    for (const b of bands) {
      const y1 = y(b.to), y2 = y(b.from);
      svg.appendChild(el('rect', {
        class: 'band', x: padL, y: y1.toFixed(1),
        width: plotW, height: (y2 - y1).toFixed(1), fill: riskToken(b.band),
      }));
    }

    if (axis) {
      // Interior band boundaries (every `from` except the bottom of the scale).
      for (const v of bands.map(b => b.from).filter(v => v > 0)) {
        svg.appendChild(el('line', {
          class: 'grid-line', x1: padL, y1: y(v).toFixed(1), x2: W - padR, y2: y(v).toFixed(1),
        }));
        svg.appendChild(el('text', { class: 'axis-label', x: 6, y: (y(v) + 3).toFixed(1) }, String(v)));
      }
    }

    const cur = data[data.length - 1].s;
    const stroke = bandColor(cur);
    const pts = data.map((d, i) => x(i).toFixed(1) + ',' + y(d.s).toFixed(1));

    svg.appendChild(el('path', {
      class: 'area',
      d: 'M ' + x(0).toFixed(1) + ',' + (padT + plotH).toFixed(1) + ' L ' + pts.join(' L ') +
         ' L ' + x(data.length - 1).toFixed(1) + ',' + (padT + plotH).toFixed(1) + ' Z',
      fill: stroke, 'fill-opacity': '0.12',
    }));
    svg.appendChild(el('polyline', { class: 'line', points: pts.join(' '), stroke: stroke }));

    if (axis) {
      data.forEach((d, i) => {
        svg.appendChild(el('circle', {
          class: 'dot', cx: x(i).toFixed(1), cy: y(d.s).toFixed(1), r: 3, fill: bandColor(d.s),
        }));
      });
      svg.appendChild(el('text', {
        class: 'axis-label', x: padL, y: H - 6, 'text-anchor': 'start',
      }, String(data[0].d)));
      svg.appendChild(el('text', {
        class: 'axis-label', x: W - padR, y: H - 6, 'text-anchor': 'end',
      }, String(data[data.length - 1].d)));
    }

    svg.appendChild(el('circle', {
      cx: x(data.length - 1).toFixed(1), cy: y(cur).toFixed(1),
      r: axis ? 4.5 : 3.5, fill: stroke, stroke: 'var(--surface)', 'stroke-width': 2,
    }));

    container.replaceChildren(svg);
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
