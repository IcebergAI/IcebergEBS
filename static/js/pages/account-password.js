// Change-password page component (#106).

document.addEventListener('alpine:init', () => {
  Alpine.data('changePassword', () => ({
    form: { current_password: '', new_password: '', confirm_password: '' },
    saving: false, error: '', success: false,
    async submit() {
      this.error = ''; this.success = false;
      if (!this.form.current_password) { this.error = 'Current password is required'; return; }
      if (!this.form.new_password) { this.error = 'New password is required'; return; }
      if (this.form.new_password !== this.form.confirm_password) { this.error = 'Passwords do not match'; return; }
      if (this.form.new_password.length < 8) { this.error = 'New password must be at least 8 characters'; return; }
      this.saving = true;
      try {
        const r = await fetch('/api/users/me/password', {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ current_password: this.form.current_password, new_password: this.form.new_password }),
        });
        if (r.ok) {
          window.location.href = '/login';
        } else {
          const data = await r.json();
          this.error = data.detail || 'Failed to change password';
        }
      } catch { this.error = 'Network error'; }
      finally { this.saving = false; }
    },
  }));
});
