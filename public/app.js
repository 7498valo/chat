const api = (path, opts = {}) => fetch('/api' + path, opts).then(r => r.json());
const $ = id => document.getElementById(id);
const authDiv = $('auth');
const chatDiv = $('chat');
let socket = null;
let token = localStorage.getItem('token');
let currentChannel = 'general';

async function init() {
  if (token) {
    try {
      const me = await api('/me', { headers: { Authorization: 'Bearer ' + token } });
      startChat(me.username, token, me.channels);
      return;
    } catch {
      localStorage.removeItem('token');
      token = null;
    }
  }
  authDiv.style.display = 'block';
}

$('btnRegister').onclick = async () => {
  const username = $('username').value.trim();
  const password = $('password').value;
  const res = await api('/register', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password })
  });
  if (res.token) {
    token = res.token;
    localStorage.setItem('token', token);
    const me = await api('/me', { headers: { Authorization: 'Bearer ' + token } });
    startChat(res.username, token, me.channels);
  } else {
    $('authError').textContent = res.error || 'Register failed';
  }
};

$('btnLogin').onclick = async () => {
  const username = $('username').value.trim();
  const password = $('password').value;
  const res = await api('/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password })
  });
  if (res.token) {
    token = res.token;
    localStorage.setItem('token', token);
    const me = await api('/me', { headers: { Authorization: 'Bearer ' + token } });
    startChat(res.username, token, me.channels);
  } else {
    $('authError').textContent = res.error || 'Login failed';
  }
};

function appendMessage(msg) {
  const d = document.createElement('div');
  d.className = 'message';
  const md = document.createElement('div');
  md.className = 'meta';
  const date = new Date(msg.ts);
  md.textContent = `${msg.author} • ${date.toLocaleString()}`;
  d.appendChild(md);
  if (msg.text) {
    const body = document.createElement('div');
    body.textContent = msg.text;
    d.appendChild(body);
  }
  if (msg.file) {
    const a = document.createElement('a');
    a.href = msg.file.url;
    a.target = '_blank';
    a.textContent = `Attachment: ${msg.file.filename}`;
    d.appendChild(a);
  }
  $('messages').appendChild(d);
  $('messages').scrollTop = $('messages').scrollHeight;
}

function startChat(username, tokenStr, channels) {
  authDiv.style.display = 'none';
  chatDiv.style.display = 'flex';
  $('me').textContent = `Logged in as ${username}`;
  const chList = $('channels');
  chList.innerHTML = '';
  channels.forEach(ch => {
    const li = document.createElement('li');
    li.textContent = ch.name;
    li.onclick = () => {
      currentChannel = ch.id;
      socket.emit('join', ch.id);
      $('messages').innerHTML = '';
    };
    chList.appendChild(li);
  });

  socket = io({ auth: { token: tokenStr } });
  socket.on('history', payload => {
    if (payload.channel !== currentChannel) return;
    $('messages').innerHTML = '';
    payload.messages.forEach(appendMessage);
  });
  socket.on('message', msg => {
    if (msg.channel !== currentChannel) return;
    appendMessage(msg);
  });

  $('msgForm').onsubmit = async ev => {
    ev.preventDefault();
    const text = $('msgInput').value.trim();
    const fileInput = $('fileInput');
    let fileMeta = null;

    if (fileInput.files.length > 0) {
      const fd = new FormData();
      fd.append('file', fileInput.files[0]);
      const res = await fetch('/api/upload', {
        method: 'POST',
        headers: { Authorization: 'Bearer ' + tokenStr },
        body: fd
      });
      fileMeta = await res.json();
    }

    if (!text && !fileMeta) return;
    socket.emit('message', { channel: currentChannel, text, file: fileMeta });
    $('msgInput').value = '';
    fileInput.value = '';
  };
}

init();
