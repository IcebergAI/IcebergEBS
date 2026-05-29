document.addEventListener('DOMContentLoaded', () => {
  const input = document.querySelector('.search input');
  if (!input) return;

  const params = new URLSearchParams(location.search);
  if (params.get('q')) input.value = params.get('q');

  document.addEventListener('keydown', (e) => {
    if (e.key === '/' && document.activeElement !== input) {
      e.preventDefault();
      input.focus();
    }
  });

  input.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      location.href = '/?q=' + encodeURIComponent(input.value.trim());
    }
  });
});
