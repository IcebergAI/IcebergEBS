// User admin page component (#106). Server data comes from the #users-data JSON
// island ({users, current_user_id, roles}). Roles (#33): admin | analyst | auditor.

document.addEventListener('alpine:init', () => {
  Alpine.data('userAdmin', () => {
    const data = readJSON('users-data') || {};
    return {
      users: data.users || [],
      currentUserId: data.current_user_id,
      roles: data.roles || ['admin', 'analyst', 'auditor'],
      showCreate: false,
      creating: false,
      createError: '',
      deleteError: '',
      form: { username: '', password: '', email: '', role: 'analyst' },
      resetForm() {
        this.form = { username: '', password: '', email: '', role: 'analyst' };
        this.createError = '';
      },
      roleHint(role) {
        return {
          admin: 'Full access: users, alert destinations and rules, settings, threat lists.',
          analyst: 'Adds, refreshes and triages extensions; cannot manage users, alerting or settings.',
          auditor: 'Read-only. Can review the audit log; every change is refused.',
        }[role] || '';
      },
      createdText(u) {
        return new Date(u.created_at).toLocaleDateString();
      },
      async createUser() {
        this.createError = '';
        if (!this.form.username.trim()) { this.createError = 'Username is required'; return; }
        if (!this.form.password) { this.createError = 'Password is required'; return; }
        this.creating = true;
        try {
          const body = { username: this.form.username.trim(), password: this.form.password, role: this.form.role };
          if (this.form.email.trim()) body.email = this.form.email.trim();
          const r = await fetch('/api/users', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
          });
          const data = await r.json();
          if (r.ok) {
            this.users.push({ ...data, created_at: data.created_at || new Date().toISOString() });
            this.showCreate = false;
            this.resetForm();
          } else this.createError = data.detail || 'Failed to create user';
        } catch { this.createError = 'Network error'; }
        finally { this.creating = false; }
      },
      async deleteUser(id, username) {
        if (!confirm(`Delete user "${username}"? Their extensions and alert rules will also be removed.`)) return;
        this.deleteError = '';
        try {
          const r = await fetch(`/api/users/${id}`, { method: 'DELETE' });
          if (r.ok) this.users = this.users.filter(u => u.id !== id);
          else {
            const data = await r.json();
            this.deleteError = data.detail || 'Delete failed';
          }
        } catch { this.deleteError = 'Network error'; }
      },
    };
  });
});
