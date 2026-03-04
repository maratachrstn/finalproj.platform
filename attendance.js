const THEME_KEY = 'vss-theme';

const themeToggle = document.getElementById('themeToggle');
const logoutBtn = document.getElementById('logoutBtn');
const userBadge = document.getElementById('userBadge');
const attendanceMsg = document.getElementById('attendanceMsg');
const attendanceForm = document.getElementById('attendanceForm');
const attendanceDate = document.getElementById('attendanceDate');
const attendanceStatus = document.getElementById('attendanceStatus');
const attendanceSubmitBtn = document.getElementById('attendanceSubmitBtn');
const totalStudentsEl = document.getElementById('totalStudents');
const presentCountEl = document.getElementById('presentCount');
const lateCountEl = document.getElementById('lateCount');
const absentCountEl = document.getElementById('absentCount');
const recordsList = document.getElementById('recordsList');

function getPreferredTheme() {
  const saved = localStorage.getItem(THEME_KEY);
  if (saved === 'light' || saved === 'dark') return saved;
  return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}

function applyTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme);
  themeToggle.setAttribute('aria-label', theme === 'dark' ? 'Enable light mode' : 'Enable dark mode');
}

function todayIso() {
  return new Date().toISOString().slice(0, 10);
}

function prettyStatus(value) {
  if (value === 'in_progress') return 'In Progress';
  return String(value || '').replace(/_/g, ' ').replace(/\b\w/g, (m) => m.toUpperCase());
}

async function getCurrentUser() {
  const response = await fetch('/api/auth/me', { credentials: 'same-origin' });
  if (!response.ok) return null;
  return response.json();
}

async function markAttendance(payload) {
  const response = await fetch('/api/attendance/mark', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'same-origin',
    body: JSON.stringify(payload)
  });
  const data = await response.json().catch(() => ({ message: 'Unexpected server response.' }));
  if (!response.ok) throw new Error(data.message || data.detail || 'Failed to save attendance.');
  return data;
}

async function getAttendanceToday(date) {
  const query = new URLSearchParams({ date }).toString();
  const response = await fetch(`/api/attendance/today?${query}`, { credentials: 'same-origin' });
  const data = await response.json().catch(() => ({ message: 'Unexpected server response.' }));
  if (!response.ok) throw new Error(data.message || data.detail || 'Failed to load attendance.');
  return data;
}

function renderSummary(summary) {
  totalStudentsEl.textContent = String(summary.totalStudents ?? 0);
  presentCountEl.textContent = String(summary.present ?? 0);
  lateCountEl.textContent = String(summary.late ?? 0);
  absentCountEl.textContent = String(summary.absent ?? 0);
}

function renderRecords(records) {
  const items = records || [];
  if (items.length === 0) {
    recordsList.innerHTML = '<article class="record-item">No attendance records for this date.</article>';
    return;
  }

  recordsList.innerHTML = items
    .map(
      (item) => `
      <article class="record-item">
        <h3>${item.fullName || '-'}</h3>
        <p class="record-meta">${item.userEmail || '-'} | ${new Date(item.createdAt).toLocaleString()}</p>
        <span class="status-badge">${prettyStatus(item.status)}</span>
      </article>
    `
    )
    .join('');
}

async function refreshAttendanceView() {
  const data = await getAttendanceToday(attendanceDate.value);
  renderSummary(data.summary || {});
  renderRecords(data.records || []);
}

applyTheme(getPreferredTheme());
attendanceDate.value = todayIso();

themeToggle.addEventListener('click', () => {
  const current = document.documentElement.getAttribute('data-theme') || 'light';
  const next = current === 'dark' ? 'light' : 'dark';
  applyTheme(next);
  localStorage.setItem(THEME_KEY, next);
});

logoutBtn.addEventListener('click', async () => {
  await fetch('/api/auth/logout', { method: 'POST', credentials: 'same-origin' });
  window.location.href = 'index.html';
});

attendanceDate.addEventListener('change', async () => {
  attendanceMsg.textContent = '';
  try {
    await refreshAttendanceView();
  } catch (error) {
    attendanceMsg.textContent = error.message || 'Unable to load attendance.';
  }
});

attendanceForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  attendanceSubmitBtn.disabled = true;
  attendanceSubmitBtn.textContent = 'Saving...';
  attendanceMsg.textContent = '';

  try {
    const result = await markAttendance({
      date: attendanceDate.value,
      status: attendanceStatus.value
    });
    attendanceMsg.textContent = `${result.message} (${prettyStatus(result.status)})`;
    await refreshAttendanceView();
  } catch (error) {
    attendanceMsg.textContent = error.message || 'Failed to save attendance.';
  } finally {
    attendanceSubmitBtn.disabled = false;
    attendanceSubmitBtn.textContent = 'Save Attendance';
  }
});

(async () => {
  const user = await getCurrentUser();
  if (!user) {
    window.location.href = 'index.html';
    return;
  }
  userBadge.textContent = `Signed in as ${user.email} (${user.role || 'student'})`;
  try {
    await refreshAttendanceView();
  } catch (error) {
    attendanceMsg.textContent = error.message || 'Unable to load attendance.';
  }
})();
