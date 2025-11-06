const API_BASE = '';

function getToken() {
  return localStorage.getItem('token') || '';
}

function setAuth(token, username) {
  localStorage.setItem('token', token);
  localStorage.setItem('username', username);
}

function clearAuth() {
  localStorage.removeItem('token');
  localStorage.removeItem('username');
}

async function api(path, options = {}) {
  const headers = options.headers || {};
  if (!headers['Content-Type'] && !(options.body instanceof FormData)) {
    headers['Content-Type'] = 'application/json';
  }
  const token = getToken();
  if (token) headers['Authorization'] = 'Bearer ' + token;
  const res = await fetch(API_BASE + path, { ...options, headers });
  const isJSON = (res.headers.get('content-type') || '').includes('application/json');
  const data = isJSON ? await res.json() : await res.text();
  if (!res.ok) throw new Error((data && data.error) || res.statusText || '请求失败');
  return data;
}

// ========== 登录/注册页 ==========
const loginBtn = document.getElementById('btn-login');
const registerBtn = document.getElementById('btn-register');

if (loginBtn) {
  loginBtn.addEventListener('click', async () => {
    const username = document.getElementById('login-username').value.trim();
    const password = document.getElementById('login-password').value;
    if (!username || !password) return alert('请输入用户名和密码');
    try {
      const data = await api('/api/login', { method: 'POST', body: JSON.stringify({ username, password }) });
      setAuth(data.token, data.username);
      location.href = './chat.html';
    } catch (e) {
      alert('登录失败：' + e.message);
    }
  });
}

if (registerBtn) {
  registerBtn.addEventListener('click', async () => {
    const username = document.getElementById('reg-username').value.trim();
    const password = document.getElementById('reg-password').value;
    if (!username || !password) return alert('请输入用户名和密码');
    try {
      await api('/api/register', { method: 'POST', body: JSON.stringify({ username, password }) });
      alert('注册成功，请登录');
    } catch (e) {
      alert('注册失败：' + e.message);
    }
  });
}

// 已登录则跳转
if (loginBtn && getToken()) {
  location.href = './chat.html';
}

// ========== 聊天页 ==========
const meNameEl = document.getElementById('me-name');
const contactsEl = document.getElementById('contacts');
const peerNameEl = document.getElementById('peer-name');
const messagesEl = document.getElementById('messages');
const inputTextEl = document.getElementById('input-text');
const sendBtn = document.getElementById('btn-send');
const logoutBtn = document.getElementById('btn-logout');

let currentPeer = '';
let latestSeq = 0;
let polling = false;

async function loadContacts() {
  const data = await api('/api/contacts');
  contactsEl.innerHTML = '';
  data.contacts.forEach((name) => {
    const div = document.createElement('div');
    div.className = 'contact' + (name === currentPeer ? ' active' : '');
    div.textContent = name;
    div.addEventListener('click', () => selectPeer(name));
    contactsEl.appendChild(div);
  });
}

function appendMessage(m) {
  const me = localStorage.getItem('username') || '';
  const div = document.createElement('div');
  div.className = 'msg ' + (m.from === me ? 'me' : 'other');
  div.textContent = m.text;
  messagesEl.appendChild(div);
  messagesEl.scrollTop = messagesEl.scrollHeight;
}

async function pullOnce(waitMs = 20000) {
  if (!currentPeer) return;
  try {
    const qs = `with=${encodeURIComponent(currentPeer)}&since=${latestSeq}&wait=${waitMs}`;
    const data = await api('/api/messages?' + qs);
    (data.messages || []).forEach((m) => {
      appendMessage(m);
      latestSeq = Math.max(latestSeq, m.seq);
    });
  } catch (e) {
    // 忽略错误，短暂休眠后再试
    await new Promise(r => setTimeout(r, 1000));
  }
}

async function startPolling() {
  if (polling) return; polling = true;
  while (polling) {
    await pullOnce(20000);
  }
}

async function selectPeer(name) {
  currentPeer = name;
  latestSeq = 0;
  peerNameEl.textContent = name;
  messagesEl.innerHTML = '';
  Array.from(contactsEl.children).forEach(el => {
    el.classList.toggle('active', el.textContent === name);
  });
  // 立即拉取一次并确保轮询运行
  await pullOnce(1);
  startPolling();
}

async function sendCurrent() {
  const text = (inputTextEl.value || '').trim();
  if (!text || !currentPeer) return;
  inputTextEl.value = '';
  try {
    await api('/api/send', { method: 'POST', body: JSON.stringify({ to: currentPeer, text }) });
    // 发送后立即触发一次短轮询，尽快显示
    await pullOnce(1);
  } catch (e) {
    alert('发送失败：' + e.message);
  }
}

if (sendBtn) {
  sendBtn.addEventListener('click', sendCurrent);
  inputTextEl.addEventListener('keydown', (e) => { if (e.key === 'Enter') sendCurrent(); });
}

if (logoutBtn) {
  logoutBtn.addEventListener('click', () => { clearAuth(); location.href = './'; });
}

async function initChatPage() {
  const token = getToken();
  const username = localStorage.getItem('username') || '';
  if (!token) { location.href = './'; return; }
  if (meNameEl) meNameEl.textContent = username;
  try {
    await loadContacts();
    // 默认选中第一个联系人（如果有）
    if (!currentPeer && contactsEl.firstChild) selectPeer(contactsEl.firstChild.textContent);
  } catch (e) {
    alert('加载联系人失败：' + e.message);
  }
}

if (messagesEl) {
  initChatPage();
}


