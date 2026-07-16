// Bulk import page component (#106). The progress/summary labels that used to be
// template literals in x-text directives are getters/methods here — the Alpine
// CSP build's expression parser doesn't support template literals.

document.addEventListener('alpine:init', () => {
  Alpine.data('bulkImport', () => ({
    text: '',
    loading: false,
    error: '',
    summary: null,
    done: 0,
    total: 0,
    get lineCount() {
      return this.text.split('\n').map(l => l.trim()).filter(l => l && !l.startsWith('#')).length;
    },
    get progressLabel() {
      return `Importing… (${this.done}/${this.total})`;
    },
    get lineCountLabel() {
      return `${this.lineCount} line${this.lineCount === 1 ? '' : 's'}`;
    },
    summaryLabel(kind) {
      if (!this.summary) return '';
      const labels = { added: 'added', duplicates: 'duplicate', invalid: 'invalid', errors: 'failed' };
      return `${this.summary[kind]} ${labels[kind]}`;
    },
    openResult(res) {
      if (res.id) window.location = '/extensions/' + res.id;
    },
    async submit() {
      this.error = '';
      this.summary = null;
      const lines = this.lineCount;
      if (lines === 0) { this.error = 'Paste at least one extension'; return; }
      if (lines > 100) { this.error = `Too many — max 100 per import (got ${lines})`; return; }
      this.loading = true;
      this.total = lines;
      this.done = 0;
      try {
        const r = await fetch('/api/extensions/bulk', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ text: this.text }),
        });
        const data = await r.json();
        if (r.ok) this.summary = data;
        else this.error = data.detail || 'Import failed';
      } catch { this.error = 'Network error'; }
      finally { this.loading = false; this.done = this.total; }
    },
  }));
});
