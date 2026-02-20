const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const multer = require('multer');
const path = require('path');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const fs = require('fs');

const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret_change_me';
const PORT = process.env.PORT || 3000;

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });

app.use(express.json());
app.use(cors());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use(express.static(path.join(__dirname, 'public')));

const UPLOAD_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

const upload = multer({ dest: UPLOAD_DIR });

const users = [];
const channels = [{ id: 'general', name: 'General' }];
const messages = [];

let nextUserId = 1;
let nextMessageId = 1;

function authenticate(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) return res.status(401).json({ error: 'Unauthorized' });
  const token = auth.slice(7);
  try {
    const data = jwt.verify(token, JWT_SECRET);
    req.user = { id: data.id, username: data.username };
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

app.post('/api/register', async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'username and password required' });
  if (users.find(u => u.username === username)) return res.status(400).json({ error: 'username exists' });
  const hash = await bcrypt.hash(password, 10);
  const user = { id: nextUserId++, username, passwordHash: hash };
  users.push(user);
  const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET);
  res.json({ token, username: user.username });
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'username and password required' });
  const user = users.find(u => u.username === username);
  if (!user) return res.status(400).json({ error: 'invalid credentials' });
  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) return res.status(400).json({ error: 'invalid credentials' });
  const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET);
  res.json({ token, username: user.username });
});

app.get('/api/me', authenticate, (req, res) => {
  res.json({ id: req.user.id, username: req.user.username, channels });
});

app.post('/api/upload', authenticate, upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'no file' });
  const fileUrl = `/uploads/${path.basename(req.file.path)}`;
  const meta = { filename: req.file.originalname, size: req.file.size, url: fileUrl };
  res.json(meta);
});

io.use((socket, next) => {
  const token = socket.handshake.auth && socket.handshake.auth.token;
  if (!token) return next(new Error('Unauthorized'));
  try {
    const data = jwt.verify(token, JWT_SECRET);
    socket.user = { id: data.id, username: data.username };
    next();
  } catch {
    next(new Error('Invalid token'));
  }
});

io.on('connection', socket => {
  const user = socket.user;
  const defaultChannel = 'general';
  socket.join(defaultChannel);

  const history = messages.filter(m => m.channel === defaultChannel).slice(-200);
  socket.emit('history', { channel: defaultChannel, messages: history });

  socket.on('message', data => {
    const channel = data.channel || defaultChannel;
    const text = typeof data.text === 'string' ? data.text.trim() : '';
    const file = data.file || null;
    if (!text && !file) return;
    const msg = {
      id: nextMessageId++,
      channel,
      author: user.username,
      text,
      file,
      ts: Date.now(),
    };
    messages.push(msg);
    io.to(channel).emit('message', msg);
  });

  socket.on('join', channelId => {
    socket.join(channelId);
    const history = messages.filter(m => m.channel === channelId).slice(-200);
    socket.emit('history', { channel: channelId, messages: history });
  });
});

server.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
