// Outbound-proxy admin page component (#216). Server data comes from the
// #proxy-data JSON island ({mode, proxy_url, no_proxy, updated_at}); the
// egress-target labels are fetched from /api/proxy/targets on init.

document.addEventListener('alpine:init', () => {
  Alpine.data('proxyAdmin', () => {
    const data = readJSON('proxy-data') || {};
    return {
      form: {
        mode: data.mode || 'SYSTEM',
        proxy_url: data.proxy_url || '',
        no_proxy: data.no_proxy || '',
      },
      saving: false,
      saveError: '',
      saveOk: false,
      targets: [],
      testTarget: '',
      testing: false,
      testResult: '',
      testOk: false,
      testVia: '',
      get explicitMode() {
        return this.form.mode === 'EXPLICIT';
      },
      async init() {
        try {
          const r = await fetch('/api/proxy/targets');
          if (r.ok) {
            const data = await r.json();
            this.targets = data.targets || [];
            if (this.targets.length) this.testTarget = this.targets[0];
          }
        } catch { /* leave the target list empty */ }
      },
      async save() {
        this.saveError = '';
        this.saveOk = false;
        if (this.form.mode === 'EXPLICIT' && !this.form.proxy_url.trim()) {
          this.saveError = 'Explicit mode requires a proxy URL';
          return;
        }
        this.saving = true;
        try {
          const r = await fetch('/api/proxy/settings', {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              mode: this.form.mode,
              proxy_url: this.form.proxy_url.trim(),
              no_proxy: this.form.no_proxy.trim(),
            }),
          });
          const data = await r.json();
          if (r.ok) {
            this.form.mode = data.mode;
            this.form.proxy_url = data.proxy_url;
            this.form.no_proxy = data.no_proxy;
            this.saveOk = true;
          } else {
            this.saveError = typeof data.detail === 'string'
              ? data.detail
              : (data.detail && data.detail[0] && data.detail[0].msg) || 'Save failed';
          }
        } catch { this.saveError = 'Network error'; }
        finally { this.saving = false; }
      },
      async runTest() {
        this.testResult = '';
        this.testVia = '';
        this.testing = true;
        try {
          const r = await fetch('/api/proxy/test', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target: this.testTarget }),
          });
          const data = await r.json();
          if (r.ok) {
            this.testResult = data.result;
            this.testOk = data.result.indexOf('ok:') === 0;
            this.testVia = data.via_proxy ? 'Routed through the proxy.' : 'Connected directly (no proxy for this target).';
          } else {
            this.testResult = typeof data.detail === 'string' ? data.detail : 'Test failed';
            this.testOk = false;
          }
        } catch {
          this.testResult = 'Network error';
          this.testOk = false;
        }
        finally { this.testing = false; }
      },
    };
  });
});
