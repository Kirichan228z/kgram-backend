const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');

dotenv.config();

const app = express();
const port = process.env.PORT || 5000;

// Подключение к базе данных (Supabase PostgreSQL)
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Middleware
app.use(cors({ origin: '*' }));
app.use(express.json());

// ============================================
// HEALTH CHECK
// ============================================
app.get('/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    timestamp: new Date().toISOString(),
    uptime: process.uptime()
  });
});

// ============================================
// РЕГИСТРАЦИЯ
// ============================================
app.post('/api/auth/register', async (req, res) => {
  try {
    const { phone, username, password, firstName, lastName, email } = req.body;
    
    console.log('📝 Register attempt:', { phone, username });
    
    // Проверка существования пользователя
    const checkUser = await pool.query(
      'SELECT * FROM users WHERE phone = $1 OR username = $2',
      [phone, username]
    );
    
    if (checkUser.rows.length > 0) {
      return res.status(409).json({ 
        success: false,
        message: 'Пользователь с таким номером или именем уже существует' 
      });
    }
    
    // Хеширование пароля
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // Создание пользователя
    const result = await pool.query(
      `INSERT INTO users (phone, username, password_hash, first_name, last_name, email)
       VALUES ($1, $2, $3, $4, $5, $6) 
       RETURNING id, username, phone, email, first_name, last_name, created_at`,
      [phone, username, hashedPassword, firstName || null, lastName || null, email || null]
    );
    
    const user = result.rows[0];
    
    // Создание JWT токена
    const token = jwt.sign(
      { userId: user.id, username: user.username },
      process.env.JWT_SECRET || 'kgram_secret_2026',
      { expiresIn: '7d' }
    );
    
    console.log('✅ User registered:', user.username);
    
    res.status(201).json({
      success: true,
      token,
      user: {
        id: user.id,
        username: user.username,
        phone: user.phone,
        email: user.email,
        firstName: user.first_name,
        lastName: user.last_name,
        createdAt: user.created_at
      }
    });
  } catch (error) {
    console.error('❌ Register error:', error);
    res.status(500).json({ 
      success: false,
      message: 'Внутренняя ошибка сервера' 
    });
  }
});

// ============================================
// ВХОД
// ============================================
app.post('/api/auth/login', async (req, res) => {
  try {
    const { phone, password } = req.body;
    
    console.log('🔑 Login attempt:', phone);
    
    const result = await pool.query(
      'SELECT * FROM users WHERE phone = $1',
      [phone]
    );
    
    if (result.rows.length === 0) {
      return res.status(401).json({ 
        success: false,
        message: 'Неверный логин или пароль' 
      });
    }
    
    const user = result.rows[0];
    const isValid = await bcrypt.compare(password, user.password_hash);
    
    if (!isValid) {
      return res.status(401).json({ 
        success: false,
        message: 'Неверный логин или пароль' 
      });
    }
    
    const token = jwt.sign(
      { userId: user.id, username: user.username },
      process.env.JWT_SECRET || 'kgram_secret_2026',
      { expiresIn: '7d' }
    );
    
    console.log('✅ User logged in:', user.username);
    
    res.json({
      success: true,
      token,
      user: {
        id: user.id,
        username: user.username,
        phone: user.phone,
        email: user.email,
        firstName: user.first_name,
        lastName: user.last_name,
        avatarUrl: user.avatar_url,
        bio: user.bio,
        status: user.status || 'online',
        createdAt: user.created_at
      }
    });
  } catch (error) {
    console.error('❌ Login error:', error);
    res.status(500).json({ 
      success: false,
      message: 'Внутренняя ошибка сервера' 
    });
  }
});

// ============================================
// ОБНОВЛЕНИЕ ТОКЕНА
// ============================================
app.post('/api/auth/refresh', async (req, res) => {
  try {
    const { refreshToken } = req.body;
    
    if (!refreshToken) {
      return res.status(400).json({ 
        success: false,
        message: 'Refresh token required' 
      });
    }
    
    const decoded = jwt.verify(refreshToken, process.env.JWT_SECRET || 'kgram_secret_2026');
    
    const result = await pool.query(
      'SELECT id, username FROM users WHERE id = $1',
      [decoded.userId]
    );
    
    if (result.rows.length === 0) {
      return res.status(401).json({ 
        success: false,
        message: 'User not found' 
      });
    }
    
    const user = result.rows[0];
    const token = jwt.sign(
      { userId: user.id, username: user.username },
      process.env.JWT_SECRET || 'kgram_secret_2026',
      { expiresIn: '7d' }
    );
    
    res.json({
      success: true,
      token
    });
  } catch (error) {
    console.error('❌ Refresh error:', error);
    res.status(401).json({ 
      success: false,
      message: 'Invalid refresh token' 
    });
  }
});

// ============================================
// ПОЛУЧЕНИЕ ПОЛЬЗОВАТЕЛЯ ПО ID
// ============================================
app.get('/api/users/:id', async (req, res) => {
  try {
    const { id } = req.params;
    
    const result = await pool.query(
      `SELECT id, username, phone, email, first_name, last_name, avatar_url, bio, status, is_verified, created_at 
       FROM users WHERE id = $1`,
      [id]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ 
        success: false,
        message: 'Пользователь не найден' 
      });
    }
    
    const user = result.rows[0];
    res.json({
      success: true,
      user: {
        id: user.id,
        username: user.username,
        phone: user.phone,
        email: user.email,
        firstName: user.first_name,
        lastName: user.last_name,
        avatarUrl: user.avatar_url,
        bio: user.bio,
        status: user.status,
        isVerified: user.is_verified,
        createdAt: user.created_at
      }
    });
  } catch (error) {
    console.error('❌ Get user error:', error);
    res.status(500).json({ 
      success: false,
      message: 'Внутренняя ошибка сервера' 
    });
  }
});

// ============================================
// ПОИСК ПОЛЬЗОВАТЕЛЕЙ
// ============================================
app.get('/api/users/search/:query', async (req, res) => {
  try {
    const { query } = req.params;
    
    const result = await pool.query(
      `SELECT id, username, first_name, last_name, avatar_url, status 
       FROM users 
       WHERE username ILIKE $1 
          OR first_name ILIKE $1 
          OR last_name ILIKE $1
       LIMIT 20`,
      [`%${query}%`]
    );
    
    res.json({
      success: true,
      users: result.rows
    });
  } catch (error) {
    console.error('❌ Search error:', error);
    res.status(500).json({ 
      success: false,
      message: 'Внутренняя ошибка сервера' 
    });
  }
});

// ============================================
// ОБНОВЛЕНИЕ ПОЛЬЗОВАТЕЛЯ
// ============================================
app.put('/api/users/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { firstName, lastName, bio, avatarUrl } = req.body;
    
    const result = await pool.query(
      `UPDATE users 
       SET first_name = COALESCE($1, first_name),
           last_name = COALESCE($2, last_name),
           bio = COALESCE($3, bio),
           avatar_url = COALESCE($4, avatar_url)
       WHERE id = $5
       RETURNING id, username, phone, email, first_name, last_name, avatar_url, bio, status, created_at`,
      [firstName, lastName, bio, avatarUrl, id]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ 
        success: false,
        message: 'Пользователь не найден' 
      });
    }
    
    const user = result.rows[0];
    res.json({
      success: true,
      user: {
        id: user.id,
        username: user.username,
        phone: user.phone,
        email: user.email,
        firstName: user.first_name,
        lastName: user.last_name,
        avatarUrl: user.avatar_url,
        bio: user.bio,
        status: user.status,
        createdAt: user.created_at
      }
    });
  } catch (error) {
    console.error('❌ Update user error:', error);
    res.status(500).json({ 
      success: false,
      message: 'Внутренняя ошибка сервера' 
    });
  }
});

// ============================================
// ЗАПУСК СЕРВЕРА
// ============================================
app.listen(port, () => {
  console.log(`🚀 KGram Server running on port ${port}`);
  console.log(`🌐 Health: http://localhost:${port}/health`);
  console.log(`📡 API: http://localhost:${port}/api`);
});
