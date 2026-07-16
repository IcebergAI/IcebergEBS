// Dashboard page component (#106). Extensions come from the #dashboard-data JSON
// island; formatting that used to live in directive expressions (`??`, `new
// Date(...)`) is methods here because the Alpine CSP build's expression parser
// doesn't support those forms.

document.addEventListener('alpine:init', () => {
  Alpine.data('dashboardData', () => ({
    extensions: readJSON('dashboard-data') || [],
    riskLevel(score) {
      if (score == null) return 'unknown';
      if (score >= 75) return 'critical';
      if (score >= 50) return 'high';
      if (score >= 25) return 'medium';
      return 'low';
    },
    scoreColor(score) {
      return {
        critical: 'oklch(0.60 0.18 22)',
        high:     'oklch(0.68 0.16 50)',
        medium:   'oklch(0.74 0.14 85)',
        low:      'oklch(0.66 0.14 155)',
        unknown:  'oklch(0.58 0.012 245)',
      }[this.riskLevel(score)];
    },
    scoreText(ext) {
      return ext.risk_score == null ? '—' : String(ext.risk_score);
    },
    installsText(ext) {
      return ext.install_count == null ? '—' : ext.install_count.toLocaleString();
    },
    updatedText(ext) {
      return ext.last_updated ? new Date(ext.last_updated).toLocaleDateString() : '—';
    },
    openExt(ext) {
      window.location = '/extensions/' + ext.id;
    },
    refreshExt(id) {
      fetch('/api/extensions/' + id + '/refresh', { method: 'POST' })
        .then(r => r.ok ? location.reload() : alert('Refresh failed'));
    },
  }));
});
