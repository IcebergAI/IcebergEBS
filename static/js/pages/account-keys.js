// API keys page component (#106). Keys come from the #keys-data JSON island.

document.addEventListener('alpine:init', () => {
  Alpine.data('apiKeysPage', () => ({
    keys: readJSON('keys-data') || [],
    showAdd: false,
    saving: false,
    form: { label: '', readonly: false },
    formError: '',
    globalError: '',
    newKey: '',
    copied: false,

    formatDate(iso) {
      return new Date(iso).toLocaleString(undefined, { dateStyle: 'short', timeStyle: 'short' });
    },
    keyDisplay(k) {
      return k.key_prefix ? k.key_prefix + '…' + k.key_suffix : '—';
    },
    resetForm() {
      this.form = { label: '', readonly: false };
      this.formError = '';
    },
    async copyKey() {
      try {
        await navigator.clipboard.writeText(this.newKey);
        this.copied = true;
        setTimeout(() => { this.copied = false; }, 2000);
      } catch { /* clipboard unavailable */ }
    },
    async createKey() {
      this.formError = '';
      if (!this.form.label.trim()) { this.formError = 'Label is required'; return; }
      this.saving = true;
      try {
        const r = await fetch('/api/keys', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ label: this.form.label.trim(), readonly: this.form.readonly }),
        });
        const data = await r.json();
        if (r.ok) {
          this.keys.push({
            id: data.id,
            label: data.label,
            key_prefix: data.key_prefix,
            key_suffix: data.key_suffix,
            readonly: data.readonly,
            created_at: data.created_at,
            last_used_at: data.last_used_at,
          });
          this.newKey = data.raw_key;
          this.copied = false;
          this.showAdd = false;
          this.resetForm();
          window.scrollTo({ top: 0, behavior: 'smooth' });
        } else {
          this.formError = data.detail || 'Failed to create key';
        }
      } catch { this.formError = 'Network error'; }
      finally { this.saving = false; }
    },
    async revokeKey(id) {
      if (!confirm('Revoke this API key? Any integrations using it will stop working immediately.')) return;
      const r = await fetch(`/api/keys/${id}`, { method: 'DELETE' });
      if (r.ok) {
        this.keys = this.keys.filter(k => k.id !== id);
      } else {
        this.globalError = 'Failed to revoke key';
      }
    },
  }));
});
