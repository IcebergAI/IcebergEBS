// User admin page component (#106). Server data comes from the #users-data JSON
// island ({users, current_user_id}).

document.addEventListener('alpine:init', () => {
  Alpine.data('userAdmin', () => {
    const data = readJSON('users-data') || {};
    return {
      users: data.users || [],
      currentUserId: data.current_user_id,
      showCreate: false,
      creating: false,
      createError: '',
      deleteError: '',
      form: { username: '', password: '', email: '', is_admin: false },
      resetForm() {
        this.form = { username: '', password: '', email: '', is_admin: false };
        this.createError = '';
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
          const body = { username: this.form.username.trim(), password: this.form.password, is_admin: this.form.is_admin };
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
