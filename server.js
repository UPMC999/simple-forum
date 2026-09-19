const express = require('express');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const mysql = require('mysql2/promise');
const path = require('path');

const app = express();

// MySQL 数据库连接池
let pool;

async function initDB() {
  // Railway MySQL 提供 DATABASE_URL，也支持单独的环境变量
  let config;
  if (process.env.DATABASE_URL) {
    // Railway MySQL 插件格式: mysql://user:password@host:port/database
    const url = new URL(process.env.DATABASE_URL);
    config = {
      host: url.hostname,
      port: parseInt(url.port || '3306'),
      user: url.username,
      password: url.password,
      database: url.pathname.slice(1)
    };
  } else {
    config = {
      host: process.env.MYSQLHOST,
      port: parseInt(process.env.MYSQLPORT || '3306'),
      user: process.env.MYSQLUSER,
      password: process.env.MYSQLPASSWORD,
      database: process.env.MYSQLDATABASE
    };
  }

  pool = mysql.createPool({...config, waitForConnections: true, connectionLimit: 10, queueLimit: 0});

  // 创建表
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id INT AUTO_INCREMENT PRIMARY KEY,
      username VARCHAR(50) UNIQUE NOT NULL,
      password VARCHAR(255) NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);
  console.log('数据库表已初始化');
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
    await pool.query(
      'INSERT INTO users (username, password) VALUES (?, ?)',
      [username, hashedPassword]
    );
    
    res.json({ success: true, message: '注册成功！请登录' });
  } catch (error) {
    if (error.code === 'ER_DUP_ENTRY') {
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
    const [rows] = await pool.query(
      'SELECT * FROM users WHERE username = ?',
      [username]
    );
    
    if (rows.length === 0) {
      return res.json({ success: false, message: '用户名或密码错误' });
    }
    
    const user = rows[0];
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
