// Add-extension page component (#106). Formerly an inline x-data object literal
// with methods — a hard blocker for the Alpine CSP build, which cannot parse
// method definitions inside the x-data attribute.

document.addEventListener('alpine:init', () => {
  Alpine.data('addExtension', () => ({
    store: '',
    extensionId: '',
    loading: false,
    error: '',
    detectStore() {
      const v = this.extensionId.trim();
      if (v.includes('chromewebstore.google.com') || v.includes('chrome.google.com/webstore')) this.store = 'chrome';
      else if (v.includes('marketplace.visualstudio.com')) this.store = 'vscode';
      else if (v.includes('microsoftedge.microsoft.com')) this.store = 'edge';
    },
    async submit() {
      this.error = '';
      if (!this.store) { this.error = 'Select a store'; return; }
      if (!this.extensionId.trim()) { this.error = 'Enter an extension ID or URL'; return; }
      this.loading = true;
      try {
        const r = await fetch('/api/extensions', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ store: this.store, extension_id: this.extensionId.trim() }),
        });
        const data = await r.json();
        if (r.ok) window.location.href = '/extensions/' + data.id;
        else this.error = data.detail || 'Failed to add extension';
      } catch { this.error = 'Network error'; }
      finally { this.loading = false; }
    },
  }));
});
