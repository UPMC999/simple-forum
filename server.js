const express = require('express');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const mysql = require('mysql2/promise');
const path = require('path');

const app = express();

// MySQL 数据库连接池
let pool;

async function initDB() {
  let config;
  if (process.env.DATABASE_URL) {
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
  await pool.query(`
    CREATE TABLE IF NOT EXISTS posts (
      id INT AUTO_INCREMENT PRIMARY KEY,
      user_id INT NOT NULL,
      username VARCHAR(50) NOT NULL,
      title VARCHAR(200) NOT NULL,
      content TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id)
    )
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS comments (
      id INT AUTO_INCREMENT PRIMARY KEY,
      post_id INT NOT NULL,
      user_id INT NOT NULL,
      username VARCHAR(50) NOT NULL,
      content TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (post_id) REFERENCES posts(id),
      FOREIGN KEY (user_id) REFERENCES users(id)
    )
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS follows (
      id INT AUTO_INCREMENT PRIMARY KEY,
      follower_id INT NOT NULL,
      following_id INT NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      UNIQUE KEY unique_follow (follower_id, following_id),
      FOREIGN KEY (follower_id) REFERENCES users(id),
      FOREIGN KEY (following_id) REFERENCES users(id)
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
    return res.status(401).json({ error: '请先登录' });
  }
  next();
};

// ============ 认证相关 ============

// 路由：主页
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
    const [rows] = await pool.query('SELECT * FROM users WHERE username = ?', [username]);
    
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

// 路由：获取当前用户
app.get('/api/current-user', (req, res) => {
  if (req.session.userId) {
    res.json({ loggedIn: true, username: req.session.username, userId: req.session.userId });
  } else {
    res.json({ loggedIn: false });
  }
});

// ============ 发帖相关 ============

// 获取帖子列表
app.get('/api/posts', async (req, res) => {
  try {
    const [rows] = await pool.query(`
      SELECT posts.*, users.username,
             (SELECT COUNT(*) FROM comments WHERE comments.post_id = posts.id) as comment_count
      FROM posts
      JOIN users ON posts.user_id = users.id
      ORDER BY posts.created_at DESC
      LIMIT 50
    `);
    res.json(rows);
  } catch (error) {
    console.error('获取帖子失败:', error);
    res.status(500).json({ error: '获取帖子失败' });
  }
});

// 发帖
app.post('/api/posts', requireAuth, async (req, res) => {
  const { title, content } = req.body;
  
  if (!title || !content) {
    return res.status(400).json({ error: '标题和内容不能为空' });
  }
  
  if (title.length > 200) {
    return res.status(400).json({ error: '标题不能超过200个字符' });
  }
  
  try {
    const [result] = await pool.query(
      'INSERT INTO posts (user_id, username, title, content) VALUES (?, ?, ?, ?)',
      [req.session.userId, req.session.username, title, content]
    );
    res.json({ success: true, id: result.insertId, message: '发帖成功！' });
  } catch (error) {
    console.error('发帖失败:', error);
    res.status(500).json({ error: '发帖失败，请重试' });
  }
});

// 获取单个帖子及评论
app.get('/api/posts/:id', async (req, res) => {
  try {
    const [posts] = await pool.query(`
      SELECT posts.*, users.username,
             (SELECT COUNT(*) FROM comments WHERE comments.post_id = posts.id) as comment_count
      FROM posts
      JOIN users ON posts.user_id = users.id
      WHERE posts.id = ?
    `, [req.params.id]);
    
    if (posts.length === 0) {
      return res.status(404).json({ error: '帖子不存在' });
    }
    
    const [comments] = await pool.query(`
      SELECT comments.*, users.username
      FROM comments
      JOIN users ON comments.user_id = users.id
      WHERE comments.post_id = ?
      ORDER BY comments.created_at ASC
    `, [req.params.id]);
    
    res.json({ post: posts[0], comments });
  } catch (error) {
    console.error('获取帖子详情失败:', error);
    res.status(500).json({ error: '获取帖子详情失败' });
  }
});

// 删除帖子
app.delete('/api/posts/:id', requireAuth, async (req, res) => {
  try {
    const [result] = await pool.query(
      'DELETE FROM posts WHERE id = ? AND user_id = ?',
      [req.params.id, req.session.userId]
    );
    if (result.affectedRows === 0) {
      return res.status(403).json({ error: '无权删除此帖子' });
    }
    res.json({ success: true, message: '删除成功' });
  } catch (error) {
    console.error('删除帖子失败:', error);
    res.status(500).json({ error: '删除失败' });
  }
});

// ============ 评论相关 ============

// 发表评论
app.post('/api/comments', requireAuth, async (req, res) => {
  const { postId, content } = req.body;
  
  if (!postId || !content) {
    return res.status(400).json({ error: '帖子ID和内容不能为空' });
  }
  
  try {
    const [result] = await pool.query(
      'INSERT INTO comments (post_id, user_id, username, content) VALUES (?, ?, ?, ?)',
      [postId, req.session.userId, req.session.username, content]
    );
    res.json({ success: true, id: result.insertId, message: '评论成功！' });
  } catch (error) {
    console.error('评论失败:', error);
    res.status(500).json({ error: '评论失败，请重试' });
  }
});

// 删除评论
app.delete('/api/comments/:id', requireAuth, async (req, res) => {
  try {
    const [result] = await pool.query(
      'DELETE FROM comments WHERE id = ? AND user_id = ?',
      [req.params.id, req.session.userId]
    );
    if (result.affectedRows === 0) {
      return res.status(403).json({ error: '无权删除此评论' });
    }
    res.json({ success: true, message: '删除成功' });
  } catch (error) {
    console.error('删除评论失败:', error);
    res.status(500).json({ error: '删除失败' });
  }
});

// ============ 社交相关 ============

// 获取所有用户
app.get('/api/users', requireAuth, async (req, res) => {
  try {
    const [rows] = await pool.query(
      'SELECT id, username, created_at FROM users WHERE id != ?',
      [req.session.userId]
    );
    res.json(rows);
  } catch (error) {
    console.error('获取用户列表失败:', error);
    res.status(500).json({ error: '获取用户列表失败' });
  }
});

// 关注用户
app.post('/api/follow', requireAuth, async (req, res) => {
  const { userId } = req.body;
  
  if (!userId || parseInt(userId) === req.session.userId) {
    return res.status(400).json({ error: '无效的用户' });
  }
  
  try {
    await pool.query(
      'INSERT IGNORE INTO follows (follower_id, following_id) VALUES (?, ?)',
      [req.session.userId, userId]
    );
    res.json({ success: true, message: '关注成功！' });
  } catch (error) {
    console.error('关注失败:', error);
    res.status(500).json({ error: '关注失败' });
  }
});

// 取消关注
app.delete('/api/follow/:userId', requireAuth, async (req, res) => {
  try {
    await pool.query(
      'DELETE FROM follows WHERE follower_id = ? AND following_id = ?',
      [req.session.userId, req.params.userId]
    );
    res.json({ success: true, message: '已取消关注' });
  } catch (error) {
    console.error('取消关注失败:', error);
    res.status(500).json({ error: '操作失败' });
  }
});

// 获取关注列表
app.get('/api/following', requireAuth, async (req, res) => {
  try {
    const [rows] = await pool.query(`
      SELECT users.id, users.username, users.created_at
      FROM follows
      JOIN users ON follows.following_id = users.id
      WHERE follows.follower_id = ?
    `, [req.session.userId]);
    res.json(rows);
  } catch (error) {
    console.error('获取关注列表失败:', error);
    res.status(500).json({ error: '获取关注列表失败' });
  }
});

// 获取粉丝列表
app.get('/api/followers', requireAuth, async (req, res) => {
  try {
    const [rows] = await pool.query(`
      SELECT users.id, users.username, users.created_at
      FROM follows
      JOIN users ON follows.follower_id = users.id
      WHERE follows.following_id = ?
    `, [req.session.userId]);
    res.json(rows);
  } catch (error) {
    console.error('获取粉丝列表失败:', error);
    res.status(500).json({ error: '获取粉丝列表失败' });
  }
});

// ============ 页面路由 ============

// 仪表盘
app.get('/dashboard', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// 发帖页面
app.get('/posts', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'posts.html'));
});

// 帖子详情页面
app.get('/post/:id', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'post.html'));
});

// 社交页面
app.get('/social', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'social.html'));
});

const PORT = process.env.PORT || 3000;

initDB().then(() => {
  app.listen(PORT, () => {
    console.log(`论坛已启动: http://localhost:${PORT}`);
  });
}).catch(error => {
  console.error('启动失败:', error);
  process.exit(1);
});
