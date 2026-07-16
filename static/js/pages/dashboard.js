// Dashboard page component (#106). Extensions come from the #dashboard-data JSON
// island. Each row's `risk_band` is computed SERVER-side from scoring.risk_level
// (the single home of the 75/50/25 thresholds) and maps to the .risk-*/.fill-*/
// .badge-* classes here — the colours live only in app.css's --risk-* tokens
// (#105), so they follow the light/dark theme.

document.addEventListener('alpine:init', () => {
  Alpine.data('dashboardData', () => ({
    extensions: readJSON('dashboard-data') || [],
    scoreText(ext) {
      return ext.risk_score == null ? '—' : String(ext.risk_score);
    },
    installsText(ext) {
      return ext.install_count == null ? '—' : ext.install_count.toLocaleString();
    },
    updatedText(ext) {
      return ext.last_updated ? new Date(ext.last_updated).toLocaleDateString() : '—';
    },
    barStyle(ext) {
      return 'width:' + (ext.risk_score || 0) + '%';
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
