(async function roleUiGuard() {
  async function getCurrentUser() {
    try {
      const response = await fetch('/api/auth/me', { credentials: 'same-origin' });
      if (!response.ok) return null;
      return response.json();
    } catch {
      return null;
    }
  }

  const user = await getCurrentUser();
  const role = String(user?.role || '').toLowerCase();
  const canUseAttendance = role === 'professor' || role === 'administrator';

  if (!canUseAttendance) {
    document.querySelectorAll('.attendance-link').forEach((el) => {
      el.style.display = 'none';
    });
  }

  const onAttendancePage = /attendance\.html$/i.test(window.location.pathname);
  if (onAttendancePage && !canUseAttendance) {
    window.location.href = user ? 'dashboard.html' : 'index.html';
  }
})();
