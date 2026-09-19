const express = require('express');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const { Pool } = require('pg');
const path = require('path');

const app = express();

// PostgreSQL 数据库连接
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// 初始化数据库表
async function initDB() {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    console.log('数据库表已初始化');
  } catch (error) {
    console.error('数据库初始化失败:', error);
  } finally {
    client.release();
  }
}

// 中间件
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(session({
  secret: process.env.SESSION_SECRET || 'forum-secret-key-2024',
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
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (username, password) VALUES ($1, $2) RETURNING id',
      [username, hashedPassword]
    );
    
    res.json({ success: true, message: '注册成功！请登录' });
  } catch (error) {
    if (error.code === '23505') {
      res.json({ success: false, message: '用户名已存在' });
    } else {
      console.error('注册失败:', error);
      res.json({ success: false, message: '注册失败，请重试' });
    }
  }
});

// 路由：登录
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  
  if (!username || !password) {
    return res.json({ success: false, message: '请填写用户名和密码' });
  }
  
  try {
    const result = await pool.query(
      'SELECT * FROM users WHERE username = $1',
      [username]
    );
    
    if (result.rows.length === 0) {
      return res.json({ success: false, message: '用户名或密码错误' });
    }
    
    const user = result.rows[0];
    const isValid = await bcrypt.compare(password, user.password);
    
    if (!isValid) {
      return res.json({ success: false, message: '用户名或密码错误' });
    }
    
    req.session.userId = user.id;
    req.session.username = user.username;
    
    res.json({ success: true, message: '登录成功！' });
  } catch (error) {
    console.error('登录失败:', error);
    res.json({ success: false, message: '登录失败，请重试' });
  }
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

// 启动服务器
initDB().then(() => {
  app.listen(PORT, () => {
    console.log(`论坛已启动: http://localhost:${PORT}`);
  });
}).catch(error => {
  console.error('启动失败:', error);
  process.exit(1);
});
