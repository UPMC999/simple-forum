const express = require('express');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const fs = require('fs');
const path = require('path');

const app = express();
const DATA_FILE = path.join(__dirname, 'users.json');

// 加载用户数据
function loadUsers() {
  try {
    if (fs.existsSync(DATA_FILE)) {
      const data = fs.readFileSync(DATA_FILE, 'utf8');
      return JSON.parse(data);
    }
  } catch (error) {
    console.error('加载用户数据失败:', error);
  }
  return [];
}

// 保存用户数据
function saveUsers(users) {
  fs.writeFileSync(DATA_FILE, JSON.stringify(users, null, 2));
}

// 初始化
let users = loadUsers();
console.log(`已加载 ${users.length} 个用户`);

// 中间件
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(session({
  secret: 'forum-secret-key-2024',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 24 * 60 * 60 * 1000 }
}));
app.use(express.static(path.join(__dirname, 'public')));

// 登录状态检查中间件
const requireAuth = (req, res, next) => {
  if (!req.session.userId) {
    return res.redirect('/');
  }
  next();
};

// 路由：主页（登录/注册页面）
app.get('/', (req, res) => {
  if (req.session.userId) {
    return res.redirect('/dashboard');
  }
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// 路由：注册
app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;
  
  if (!username || !password) {
    return res.json({ success: false, message: '请填写用户名和密码' });
  }
  
  if (username.length < 3 || password.length < 6) {
    return res.json({ success: false, message: '用户名至少3个字符，密码至少6个字符' });
  }
  
  try {
    users = loadUsers();
    const existingUser = users.find(u => u.username === username);
    if (existingUser) {
      return res.json({ success: false, message: '用户名已存在' });
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = {
      id: Date.now(),
      username,
      password: hashedPassword,
      createdAt: new Date().toISOString()
    };
    users.push(newUser);
    saveUsers(users);
    
    res.json({ success: true, message: '注册成功！请登录' });
  } catch (error) {
    res.json({ success: false, message: '注册失败，请重试' });
  }
});

// 路由：登录
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  
  if (!username || !password) {
    return res.json({ success: false, message: '请填写用户名和密码' });
  }
  
  users = loadUsers();
  const user = users.find(u => u.username === username);
  
  if (!user) {
    return res.json({ success: false, message: '用户名或密码错误' });
  }
  
  const isValid = await bcrypt.compare(password, user.password);
  
  if (!isValid) {
    return res.json({ success: false, message: '用户名或密码错误' });
  }
  
  req.session.userId = user.id;
  req.session.username = user.username;
  
  res.json({ success: true, message: '登录成功！' });
});

// 路由：登出
app.get('/api/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/');
});

// 路由：仪表盘
app.get('/dashboard', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// 路由：获取当前用户
app.get('/api/current-user', (req, res) => {
  if (req.session.userId) {
    res.json({ loggedIn: true, username: req.session.username });
  } else {
    res.json({ loggedIn: false });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`论坛已启动: http://localhost:${PORT}`);
});
