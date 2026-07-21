const API = '/api';

/* ================= Session ================= */
function getToken() { return localStorage.getItem('vg_token'); }
function getRole() { return localStorage.getItem('vg_role'); }
function getUsername() { return localStorage.getItem('vg_username'); }
function setSession(token, role, username) {
  localStorage.setItem('vg_token', token);
  localStorage.setItem('vg_role', role);
  localStorage.setItem('vg_username', username);
}
function clearSession() {
  localStorage.removeItem('vg_token');
  localStorage.removeItem('vg_role');
  localStorage.removeItem('vg_username');
}
function requireRoleOrRedirect(...roles) {
  if (!getToken() || !roles.includes(getRole())) {
    window.location.href = '/login.html';
  }
}
function redirectHomeForRole() {
  const role = getRole();
  if (role === 'voter') window.location.href = '/voter-dashboard.html';
  else if (role === 'election_official') window.location.href = '/official-dashboard.html';
  else if (role === 'auditor') window.location.href = '/auditor-dashboard.html';
  else window.location.href = '/index.html';
}

/* ================= API ================= */
async function apiFetch(path, options = {}) {
  const headers = options.headers || {};
  headers['Content-Type'] = 'application/json';
  const token = getToken();
  if (token) headers['Authorization'] = 'Bearer ' + token;
  const res = await fetch(API + path, { ...options, headers });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || 'Request failed');
  return data;
}

/* ================= Nav configuration ================= */
const NAV_CONFIG = {
  guest: [
    { href: '/index.html', label: 'Overview', icon: 'bi-shield-check' },
    { href: '/login.html', label: 'Sign In', icon: 'bi-box-arrow-in-right' }
  ],
  voter: [
    { section: 'Main' },
    { href: '/voter-dashboard.html', label: 'Dashboard', icon: 'bi-grid-1x2-fill' },
    { href: '/vote.html', label: 'Cast Vote', icon: 'bi-check2-square' },
    { href: '/verify.html', label: 'Verify Vote', icon: 'bi-shield-check' },
    { section: 'Account' },
    { href: '/certificate.html', label: 'Certificate', icon: 'bi-patch-check' },
    { href: '/profile.html', label: 'Profile', icon: 'bi-person-circle' }
  ],
  election_official: [
    { section: 'Main' },
    { href: '/official-dashboard.html', label: 'Dashboard', icon: 'bi-grid-1x2-fill' },
    { href: '/admin.html', label: 'Manage Election', icon: 'bi-sliders' },
    { href: '/directors.html', label: 'Manage Directors', icon: 'bi-people-fill' },
    { href: '/candidates.html', label: 'Candidates', icon: 'bi-person-badge' },
    { section: 'Security' },
    { href: '/certificates.html', label: 'Certificates', icon: 'bi-patch-check' },
    { href: '/audit.html', label: 'Audit Log', icon: 'bi-journal-text' },
    { section: 'Reporting' },
    { href: '/results.html', label: 'Results', icon: 'bi-bar-chart-fill' }
  ],
  auditor: [
    { section: 'Main' },
    { href: '/auditor-dashboard.html', label: 'Dashboard', icon: 'bi-grid-1x2-fill' },
    { section: 'Oversight' },
    { href: '/audit.html', label: 'Audit Logs', icon: 'bi-journal-text' },
    { href: '/verify-integrity.html', label: 'Verify Integrity', icon: 'bi-shield-check' },
    { section: 'Reporting' },
    { href: '/results.html', label: 'Results', icon: 'bi-bar-chart-fill' }
  ]
};

const ROLE_LABEL = { voter: 'Director', election_official: 'Election Official', auditor: 'Auditor' };

/* ================= Public (pre-login) top nav ================= */
function renderNav() {
  const el = document.getElementById('nav');
  if (!el) return;
  const current = window.location.pathname.split('/').pop() || 'index.html';
  const isLogin = current === 'login.html';

  el.innerHTML = `
  <nav class="navbar navbar-expand-lg public-nav navbar-dark py-2">
    <div class="container-fluid px-3 px-lg-4">
      <a class="navbar-brand d-flex align-items-center gap-2" href="/index.html">
        <i class="bi bi-shield-lock-fill fs-5"></i>
        <span>Vote<span class="accent">Guard</span></span>
      </a>
      <button class="navbar-toggler border-0" type="button" data-bs-toggle="collapse" data-bs-target="#vgNavCollapse">
        <span class="navbar-toggler-icon"></span>
      </button>
      <div class="collapse navbar-collapse" id="vgNavCollapse">
        <ul class="navbar-nav ms-auto mb-2 mb-lg-0 align-items-lg-center gap-lg-2">
          <li class="nav-item">
            <a class="btn btn-sm ${isLogin ? 'btn-light' : 'btn-vg-primary'} rounded-3 px-3" href="/login.html">
              <i class="bi bi-box-arrow-in-right me-1"></i>Sign In
            </a>
          </li>
        </ul>
      </div>
    </div>
  </nav>`;
}

/* ================= Authenticated app shell: sidebar + topbar ================= */
function renderAppShell(pageTitle) {
  const role = getRole();
  const items = NAV_CONFIG[role] || [];
  const current = window.location.pathname.split('/').pop() || '';

  const navHtml = items.map(it => {
    if (it.section) return `<div class="nav-section-label">${it.section}</div>`;
    const active = it.href.endsWith(current) ? 'active' : '';
    return `<a class="${active}" href="${it.href}"><i class="bi ${it.icon}"></i>${it.label}</a>`;
  }).join('');

  const username = getUsername() || '';
  const initials = username.slice(0, 2).toUpperCase();

  const sidebarEl = document.getElementById('sidebar');
  if (sidebarEl) {
    sidebarEl.innerHTML = `
      <div class="sidebar-brand">
        <i class="bi bi-shield-lock-fill"></i>
        <span>Vote<span class="accent">Guard</span></span>
      </div>
      <nav class="sidebar-nav">${navHtml}</nav>
      <div class="sidebar-footer">
        <div class="avatar">${initials}</div>
        <div>
          <div class="u-name">${escapeHtml(username)}</div>
          <div class="u-role">${ROLE_LABEL[role] || role}</div>
        </div>
        <button title="Logout" onclick="doLogout()"><i class="bi bi-box-arrow-right"></i></button>
      </div>`;
  }

  const topbarEl = document.getElementById('topbar');
  if (topbarEl) {
    topbarEl.innerHTML = `
      <div class="d-flex align-items-center gap-2">
        <button class="sidebar-toggle-btn" onclick="toggleSidebar()"><i class="bi bi-list"></i></button>
        <span class="topbar-title">${escapeHtml(pageTitle || '')}</span>
      </div>
      <div class="topbar-right">
        <div class="position-relative">
          <button class="icon-btn" onclick="toggleDropdown('notifDropdown')">
            <i class="bi bi-bell"></i>
            <span class="dot d-none" id="notifBadge">0</span>
          </button>
          <div class="dropdown-panel" id="notifDropdown">
            <div class="dp-header">Notifications</div>
            <div id="notifList"><div class="dp-empty">No notifications</div></div>
          </div>
        </div>
        <div class="position-relative">
          <button class="icon-btn" onclick="toggleDropdown('userMenuPanel')"><i class="bi bi-person"></i></button>
          <div class="user-menu-panel" id="userMenuPanel">
            <div class="px-3 py-2 border-bottom">
              <div class="fw-semibold small">${escapeHtml(username)}</div>
              <div class="text-muted-sm">${ROLE_LABEL[role] || role}</div>
            </div>
            ${role === 'voter' ? '<a href="/profile.html"><i class="bi bi-person-circle"></i>Profile</a>' : ''}
            <button onclick="doLogout()"><i class="bi bi-box-arrow-right"></i>Logout</button>
          </div>
        </div>
      </div>`;
  }

  document.addEventListener('click', (e) => {
    if (!e.target.closest('.position-relative')) {
      document.querySelectorAll('.dropdown-panel.open, .user-menu-panel.open').forEach(p => p.classList.remove('open'));
    }
  });
}

function toggleSidebar() {
  document.getElementById('sidebar').classList.toggle('open');
}
function toggleDropdown(id) {
  document.querySelectorAll('.dropdown-panel, .user-menu-panel').forEach(p => {
    if (p.id !== id) p.classList.remove('open');
  });
  document.getElementById(id).classList.toggle('open');
}

/* ================= Notifications (computed client-side from real data) ================= */
function setNotifications(list) {
  const badge = document.getElementById('notifBadge');
  const listEl = document.getElementById('notifList');
  if (!badge || !listEl) return;
  if (!list || list.length === 0) {
    badge.classList.add('d-none');
    listEl.innerHTML = '<div class="dp-empty">No notifications</div>';
    return;
  }
  badge.classList.remove('d-none');
  badge.textContent = list.length > 9 ? '9+' : list.length;
  const iconFor = { info: 'bi-info-circle text-primary', warning: 'bi-exclamation-triangle text-warning', danger: 'bi-exclamation-octagon text-danger', success: 'bi-check-circle text-success' };
  listEl.innerHTML = list.map(n => `
    <div class="dp-item">
      <i class="bi ${iconFor[n.level] || iconFor.info} mt-1"></i>
      <div>${escapeHtml(n.text)}</div>
    </div>`).join('');
}

function doLogout() {
  clearSession();
  window.location.href = '/index.html';
}

/* ================= Stepper ================= */
const STEPPER_STEPS = [
  { key: 'registration', label: 'Registration', icon: 'bi-person-plus' },
  { key: 'authentication', label: 'Authentication', icon: 'bi-key' },
  { key: 'vote', label: 'Cast Vote', icon: 'bi-check2-square' },
  { key: 'verify', label: 'Vote Verification', icon: 'bi-shield-check' },
  { key: 'results', label: 'Results', icon: 'bi-bar-chart' }
];

function renderStepper(activeKey) {
  const el = document.getElementById('stepper');
  if (!el) return;
  const activeIdx = STEPPER_STEPS.findIndex(s => s.key === activeKey);
  el.innerHTML = STEPPER_STEPS.map((s, i) => {
    let cls = '';
    if (i < activeIdx) cls = 'completed';
    else if (i === activeIdx) cls = 'active';
    const iconHtml = i < activeIdx ? '<i class="bi bi-check-lg"></i>' : `<i class="bi ${s.icon}"></i>`;
    return `<li class="${cls}"><div class="step-circle">${iconHtml}</div>${s.label}</li>`;
  }).join('');
  el.className = 'vg-stepper';
}

/* ================= Alerts ================= */
function showAlert(elId, message, type) {
  const el = document.getElementById(elId);
  if (!el) return;
  const map = { error: 'danger', success: 'success', info: 'primary', warning: 'warning' };
  el.className = 'alert alert-' + (map[type] || 'primary') + ' fade-in';
  el.innerHTML = message;
  el.classList.remove('d-none');
}
function hideAlert(elId) {
  const el = document.getElementById(elId);
  if (el) el.classList.add('d-none');
}

/* ================= OTP boxes ================= */
function wireOtpBoxes(containerId, onComplete) {
  const container = document.getElementById(containerId);
  const boxes = Array.from(container.querySelectorAll('.otp-box'));
  boxes.forEach((box, idx) => {
    box.addEventListener('input', () => {
      box.value = box.value.replace(/[^0-9]/g, '').slice(0, 1);
      if (box.value && idx < boxes.length - 1) boxes[idx + 1].focus();
      checkComplete();
    });
    box.addEventListener('keydown', (e) => {
      if (e.key === 'Backspace' && !box.value && idx > 0) boxes[idx - 1].focus();
    });
    box.addEventListener('paste', (e) => {
      e.preventDefault();
      const paste = (e.clipboardData || window.clipboardData).getData('text').replace(/[^0-9]/g, '');
      paste.split('').forEach((ch, i) => { if (boxes[i]) boxes[i].value = ch; });
      const lastFilled = Math.min(paste.length, boxes.length) - 1;
      if (boxes[lastFilled]) boxes[lastFilled].focus();
      checkComplete();
    });
  });
  function checkComplete() {
    const code = boxes.map(b => b.value).join('');
    if (code.length === 6 && onComplete) onComplete(code);
  }
  return {
    getValue: () => boxes.map(b => b.value).join(''),
    focus: () => boxes[0].focus(),
    reset: () => { boxes.forEach(b => b.value = ''); boxes[0].focus(); }
  };
}

/* ================= Countdown ================= */
function startCountdown(seconds, elId, onExpire) {
  const el = document.getElementById(elId);
  let remaining = seconds;
  if (el) el.textContent = formatTime(remaining);
  const timer = setInterval(() => {
    remaining -= 1;
    if (el) el.textContent = formatTime(Math.max(remaining, 0));
    if (remaining <= 0) {
      clearInterval(timer);
      if (onExpire) onExpire();
    }
  }, 1000);
  return timer;
}
function formatTime(sec) {
  const m = Math.floor(sec / 60).toString().padStart(2, '0');
  const s = (sec % 60).toString().padStart(2, '0');
  return `${m}:${s}`;
}

/* ================= Misc utils ================= */
function escapeHtml(str) {
  if (str === undefined || str === null) return '';
  return String(str).replace(/[&<>"']/g, m => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[m]));
}
function timeAgo(iso) {
  const diff = (Date.now() - new Date(iso).getTime()) / 1000;
  if (diff < 60) return 'just now';
  if (diff < 3600) return Math.floor(diff / 60) + ' min ago';
  if (diff < 86400) return Math.floor(diff / 3600) + ' hr ago';
  return Math.floor(diff / 86400) + ' day(s) ago';
}
function daysUntil(iso) {
  return Math.ceil((new Date(iso).getTime() - Date.now()) / 86400000);
}
function downloadTextFile(filename, text) {
  const blob = new Blob([text], { type: 'text/plain' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  a.click();
}
function toCsv(rows, headers) {
  const esc = (v) => `"${String(v ?? '').replace(/"/g, '""')}"`;
  const lines = [headers.map(esc).join(',')];
  rows.forEach(r => lines.push(headers.map(h => esc(r[h])).join(',')));
  return lines.join('\n');
}
