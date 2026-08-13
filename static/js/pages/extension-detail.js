// Extension detail page component (#106). Page state comes from the #ext-data
// JSON island ({id, watchlist, findings_count, intel_count, history_count}).
// refreshNow/deleteExt/copyIndicator were bare inline `onclick=` globals — an
// inline-script surface a strict `script-src 'self'` blocks — and are methods
// now (referenced as `@click="refreshNow"` etc., Alpine passes the event).

document.addEventListener('alpine:init', () => {
  Alpine.data('extDetail', () => {
    const data = readJSON('ext-data') || {};
    return {
      tab: 'overview',
      sev: 'all',
      extId: data.id,
      watchlist: Boolean(data.watchlist),
      findingsCount: data.findings_count || 0,
      intelCount: data.intel_count || 0,
      historyCount: data.history_count || 0,
      triageStatus: data.triage_status || 'new',
      triageAssignee: data.triage_assignee || '',
      triageNotes: data.triage_notes || '',
      riskOverride: data.risk_override || 'none',
      triageSaving: false,
      triageError: false,
      triageMessage: '',
      async saveTriage() {
        this.triageSaving = true;
        this.triageError = false;
        this.triageMessage = '';
        try {
          const response = await fetch(`/api/extensions/${this.extId}/triage`, {
            method: 'PATCH',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              triage_status: this.triageStatus,
              triage_assignee: this.triageAssignee,
              triage_notes: this.triageNotes,
              risk_override: this.riskOverride,
            }),
          });
          if (response.ok) {
            this.triageMessage = 'Triage saved';
            location.reload();
            return;
          }
          const detail = await response.json();
          this.triageError = true;
          this.triageMessage = detail.detail || 'Triage could not be saved';
        } catch {
          this.triageError = true;
          this.triageMessage = 'Triage could not be saved';
        } finally {
          this.triageSaving = false;
        }
      },
      async toggleWatchlist() {
        const r = await fetch(`/api/extensions/${this.extId}/watchlist`, {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ watchlist: !this.watchlist }),
        });
        if (r.ok) this.watchlist = !this.watchlist;
      },
      async refreshNow(event) {
        const btn = event.currentTarget;
        btn.disabled = true;
        const orig = btn.innerHTML;
        btn.textContent = 'Refreshing…';
        try {
          const r = await fetch(`/api/extensions/${this.extId}/refresh`, { method: 'POST' });
          if (r.ok) location.reload();
          else {
            const d = await r.json();
            alert(d.detail || 'Refresh failed');
            btn.innerHTML = orig;
          }
        } finally {
          btn.disabled = false;
        }
      },
      async deleteExt() {
        if (!confirm('Delete this extension from tracking?')) return;
        const r = await fetch(`/api/extensions/${this.extId}`, { method: 'DELETE' });
        if (r.ok) window.location.href = '/';
        else alert('Delete failed');
      },
      async copyIndicator(event) {
        const btn = event.currentTarget;
        const value = btn.dataset.copyValue || '';
        const original = btn.textContent;
        try {
          await navigator.clipboard.writeText(value);
          btn.textContent = 'Copied';
          setTimeout(() => { btn.textContent = original; }, 1400);
        } catch {
          window.prompt('Copy indicator', value);
        }
      },
    };
  });
});
