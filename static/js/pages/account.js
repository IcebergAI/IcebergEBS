// Alerts & webhooks page component (#106). Server data comes from the
// #account-data JSON island ({destinations, rules, extensions, alert_log}).

document.addEventListener('alpine:init', () => {
  const EVENT_LABELS = {
    risk_level_change: 'Risk level change',
    publisher_change:  'Publisher change',
    permission_change: 'Permission change',
    new_version:       'New version',
  };

  const PLACEHOLDERS = {
    email: 'ops@example.com, security@example.com',
    jira: 'https://your-domain.atlassian.net',
    servicenow: 'https://your-instance.service-now.com',
  };

  Alpine.data('accountPrefs', () => {
    const data = readJSON('account-data') || {};
    return {
      destinations: (data.destinations || []).map(d => ({ ...d, _testing: false, _testMsg: '', _testOk: false })),
      rules: data.rules || [],
      extensions: data.extensions || [],
      alertLog: data.alert_log || [],
      destinationKinds: data.destination_kinds || [],
      showAddDest: false, destSaving: false, destError: '',
      destForm: { label: '', kind: 'webhook', target: '', config: {} },
      showAddRule: false, ruleSaving: false, ruleError: '',
      ruleForm: { event_type: 'risk_level_change', destination_id: '', extension_id: '' },
      logFilter: 'all',
      globalError: '',
      init() {
        if (this.destinations.length > 0) this.ruleForm.destination_id = this.destinations[0].id;
      },
      // ── Destination-kind helpers (getters/methods; CSP build forbids arrow
      //    functions and computed member access in directive expressions) ──
      get selectedKind() {
        return this.destinationKinds.find(k => k.kind === this.destForm.kind) || null;
      },
      get targetLabel() {
        return this.selectedKind ? this.selectedKind.target_label : 'Target';
      },
      get targetPlaceholder() {
        return PLACEHOLDERS[this.destForm.kind] || 'https://hooks.example.com/...';
      },
      get kindConfigFields() {
        return this.selectedKind ? this.selectedKind.config_fields : [];
      },
      get selectedKindAvailable() {
        return this.selectedKind ? this.selectedKind.available : true;
      },
      get selectedKindReason() {
        return this.selectedKind ? (this.selectedKind.unavailable_reason || '') : '';
      },
      kindLabel(kind) {
        const k = this.destinationKinds.find(x => x.kind === kind);
        return k ? k.label : kind;
      },
      getConfig(name) { return this.destForm.config[name] || ''; },
      setConfig(name, value) { this.destForm.config[name] = value; },
      onKindChange() { this.destForm.config = {}; this.destError = ''; },
      // KPI tiles — getters, because arrow functions inside directive
      // expressions are rejected by the CSP build's parser ('=>' tokenises as
      // an unexpected '>' operator).
      get enabledRuleCount() {
        return this.rules.filter(r => r.enabled).length;
      },
      get deliveredThisWeek() {
        return this.alertLog.filter(r => r.success && this.daysSince(r.sent_at) < 7).length;
      },
      get failedThisWeek() {
        return this.alertLog.filter(r => !r.success && this.daysSince(r.sent_at) < 7).length;
      },
      get filteredLog() {
        if (this.logFilter === 'all') return this.alertLog;
        return this.alertLog.filter(r => this.logFilter === 'delivered' ? r.success : !r.success);
      },
      daysSince(iso) { return (Date.now() - new Date(iso)) / 86400000; },
      async loadLog() {
        try {
          const r = await fetch('/api/alerts/log');
          if (r.ok) this.alertLog = await r.json();
          else this.globalError = 'Failed to load alert history';
        } catch { this.globalError = 'Network error loading alert history'; }
      },
      eventLabel(t) { return EVENT_LABELS[t] || t; },
      formatTime(iso) { return new Date(iso).toLocaleString(undefined, { dateStyle: 'short', timeStyle: 'short' }); },
      resetDestForm() { this.destForm = { label: '', kind: 'webhook', target: '', config: {} }; this.destError = ''; },
      resetRuleForm() {
        this.ruleForm = { event_type: 'risk_level_change', destination_id: this.destinations[0]?.id ?? '', extension_id: '' };
        this.ruleError = '';
      },
      async addDest() {
        this.destError = '';
        if (!this.destForm.label.trim()) { this.destError = 'Label is required'; return; }
        if (!this.destForm.target.trim()) { this.destError = (this.targetLabel || 'Target') + ' is required'; return; }
        if (!this.selectedKindAvailable) { this.destError = this.selectedKindReason; return; }
        this.destSaving = true;
        // Drop blank config values so optional fields aren't sent as "".
        const config = {};
        Object.keys(this.destForm.config).forEach(k => {
          const v = (this.destForm.config[k] || '').trim();
          if (v) config[k] = v;
        });
        try {
          const r = await fetch('/api/alerts/destinations', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              label: this.destForm.label.trim(),
              kind: this.destForm.kind,
              target: this.destForm.target.trim(),
              config,
            }),
          });
          const data = await r.json();
          if (r.ok) {
            this.destinations.push({ ...data, _testing: false, _testMsg: '', _testOk: false });
            if (!this.ruleForm.destination_id) this.ruleForm.destination_id = data.id;
            this.showAddDest = false;
            this.resetDestForm();
          } else this.destError = data.detail || 'Save failed';
        } catch { this.destError = 'Network error'; }
        finally { this.destSaving = false; }
      },
      async toggleDest(d) {
        const r = await fetch(`/api/alerts/destinations/${d.id}`, {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ enabled: !d.enabled }),
        });
        if (r.ok) d.enabled = !d.enabled; else this.globalError = 'Update failed';
      },
      async testDest(d) {
        d._testing = true;
        d._testMsg = '';
        try {
          const r = await fetch(`/api/alerts/destinations/${d.id}/test`, { method: 'POST' });
          const data = await r.json();
          d._testOk  = r.ok;
          d._testMsg = r.ok ? '✓ delivered' : '✗ ' + (data.detail || 'failed');
        } catch {
          d._testOk  = false;
          d._testMsg = '✗ network error';
        } finally {
          d._testing = false;
        }
        setTimeout(() => { d._testMsg = ''; }, 4000);
      },
      async deleteDest(id) {
        if (!confirm('Delete this destination? Any rules using it will also be removed.')) return;
        const r = await fetch(`/api/alerts/destinations/${id}`, { method: 'DELETE' });
        if (r.ok) {
          this.destinations = this.destinations.filter(d => d.id !== id);
          this.rules = this.rules.filter(r => r.destination_id !== id);
        } else this.globalError = 'Delete failed';
      },
      async addRule() {
        this.ruleError = '';
        if (!this.ruleForm.destination_id) { this.ruleError = 'Select a destination'; return; }
        this.ruleSaving = true;
        try {
          const body = { event_type: this.ruleForm.event_type, destination_id: Number(this.ruleForm.destination_id) };
          if (this.ruleForm.extension_id) body.extension_id = Number(this.ruleForm.extension_id);
          const r = await fetch('/api/alerts/rules', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
          });
          const data = await r.json();
          if (r.ok) {
            const dest = this.destinations.find(d => d.id === data.destination_id);
            const ext = this.extensions.find(e => e.id === data.extension_id);
            this.rules.push({ ...data, dest_label: dest?.label ?? '—', ext_name: ext?.name ?? null });
            this.showAddRule = false;
            this.resetRuleForm();
          } else this.ruleError = data.detail || 'Save failed';
        } catch { this.ruleError = 'Network error'; }
        finally { this.ruleSaving = false; }
      },
      async toggleRule(r) {
        const res = await fetch(`/api/alerts/rules/${r.id}`, {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ enabled: !r.enabled }),
        });
        if (res.ok) r.enabled = !r.enabled; else this.globalError = 'Update failed';
      },
      async deleteRule(id) {
        if (!confirm('Delete this alert rule?')) return;
        const r = await fetch(`/api/alerts/rules/${id}`, { method: 'DELETE' });
        if (r.ok) this.rules = this.rules.filter(x => x.id !== id); else this.globalError = 'Delete failed';
      },
    };
  });
});
