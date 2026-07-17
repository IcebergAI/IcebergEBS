// SSO / OIDC admin page component (#32). Server data comes from the #oidc-data
// JSON island ({settings, client_secrets_set, updated_at}); secrets never appear
// here — only per-provider set/unset booleans rendered server-side.

document.addEventListener('alpine:init', () => {
  Alpine.data('oidcAdmin', () => {
    const data = readJSON('oidc-data') || {};
    return {
      form: Object.assign({}, data.settings || {}),
      saving: false,
      saveError: '',
      saveOk: false,
      async save() {
        this.saveError = '';
        this.saveOk = false;
        this.saving = true;
        try {
          const r = await fetch('/api/oidc/settings', {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(this.form),
          });
          const body = await r.json();
          if (r.ok) {
            this.form = Object.assign({}, body.settings || {});
            this.saveOk = true;
          } else {
            this.saveError = typeof body.detail === 'string'
              ? body.detail
              : (body.detail && body.detail[0] && body.detail[0].msg) || 'Save failed';
          }
        } catch { this.saveError = 'Network error'; }
        finally { this.saving = false; }
      },
    };
  });
});
