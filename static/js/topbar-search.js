document.addEventListener('DOMContentLoaded', () => {
  const input = document.querySelector('.search input');
  if (!input) return;

  const params = new URLSearchParams(location.search);
  if (params.get('q')) input.value = params.get('q');

  document.addEventListener('keydown', (e) => {
    if (e.key !== '/') return;
    // Don't hijack '/' while the user is typing into a field — URLs, extension IDs,
    // and bulk-import lists all contain slashes, so stealing focus swallows the char.
    const el = document.activeElement;
    const tag = el && el.tagName;
    if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT' || (el && el.isContentEditable)) {
      return;
    }
    e.preventDefault();
    input.focus();
  });

  input.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      location.href = '/?q=' + encodeURIComponent(input.value.trim());
    }
  });
});
