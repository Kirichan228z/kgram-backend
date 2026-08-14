const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');

// ============================================
// WEBSOCKET (Socket.IO)
// ============================================
const http = require('http');
const socketIo = require('socket.io');

dotenv.config();

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: '*',
    credentials: true,
  },
  path: '/chat',  // ← ВАЖНО: путь для WebSocket
});

const port = process.env.PORT || 5000;

// ============================================
// БАЗА ДАННЫХ
// ============================================
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  connectionTimeoutMillis: 5000,
  idleTimeoutMillis: 30000,
  max: 10
});

// Проверка подключения к БД
pool.connect((err) => {
  if (err) {
    console.error('❌ Ошибка подключения к БД:', err.message);
  } else {
    console.log('✅ База данных подключена!');
  }
});

// ============================================
// MIDDLEWARE
// ============================================
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
    
    const checkUser = await pool.query(
      'SELECT * FROM users WHERE phone = $1 OR username = $2',
      [phone, username]
    );
    
    if (checkUser.rows.length > 0) {
      return res.status(409).json({ 
        success: false,
        message: 'Пользователь уже существует' 
      });
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
    
    const result = await pool.query(
      `INSERT INTO users (phone, username, password_hash, first_name, last_name, email)
       VALUES ($1, $2, $3, $4, $5, $6) 
       RETURNING id, username, phone, email, first_name, last_name, created_at`,
      [phone, username, hashedPassword, firstName || null, lastName || null, email || null]
    );
    
    const user = result.rows[0];
    
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
        message: 'Пользователь не найден' 
      });
    }
    
    const user = result.rows[0];
    
    if (!user.password_hash) {
      return res.status(401).json({ 
        success: false,
        message: 'Ошибка авторизации' 
      });
    }
    
    const isValid = await bcrypt.compare(password, user.password_hash);
    
    if (!isValid) {
      return res.status(401).json({ 
        success: false,
        message: 'Неверный пароль' 
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
// ПОЛУЧЕНИЕ ПОЛЬЗОВАТЕЛЯ
// ============================================
app.get('/api/users/:id', async (req, res) => {
  try {
    const { id } = req.params;
    
    const result = await pool.query(
      `SELECT id, username, phone, email, first_name, last_name, avatar_url, bio, status, created_at 
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
// WEBSOCKET (Socket.IO)
// ============================================

// Middleware для аутентификации WebSocket
io.use((socket, next) => {
  const token = socket.handshake.query.token;
  
  if (!token) {
    return next(new Error('Authentication error: no token'));
  }
  
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'kgram_secret_2026');
    socket.userId = decoded.userId;
    socket.username = decoded.username;
    console.log('🔑 WebSocket authenticated:', socket.username);
    next();
  } catch (err) {
    console.log('❌ WebSocket auth error:', err.message);
    next(new Error('Invalid token'));
  }
});

// Обработка WebSocket соединений
io.on('connection', (socket) => {
  console.log('✅ WebSocket connected:', socket.username, 'ID:', socket.userId);
  
  // Присоединяемся к комнате пользователя
  socket.join(`user:${socket.userId}`);
  
  // Уведомляем всех о новом статусе
  io.emit('userStatus', {
    userId: socket.userId,
    username: socket.username,
    status: 'online'
  });
  
  // Обработка отправки сообщения
  socket.on('sendMessage', (data) => {
    console.log('📩 Message from', socket.username, 'to', data.chatId);
    
    // Добавляем отправителя
    data.senderId = socket.userId;
    data.senderName = socket.username;
    data.timestamp = new Date().toISOString();
    
    // Отправляем всем в чате
    io.to(`chat:${data.chatId}`).emit('newMessage', data);
    
    // Подтверждение отправителю
    socket.emit('messageDelivered', {
      messageId: data.id || Date.now().toString(),
      status: 'sent'
    });
  });
  
  // Обработка статуса "печатает"
  socket.on('typing', (data) => {
    socket.to(`chat:${data.chatId}`).emit('userTyping', {
      userId: socket.userId,
      username: socket.username,
      chatId: data.chatId,
      isTyping: data.isTyping
    });
  });
  
  // Обработка прочтения сообщения
  socket.on('readMessage', (data) => {
    io.to(`chat:${data.chatId}`).emit('messageRead', {
      messageId: data.messageId,
      userId: socket.userId,
      username: socket.username
    });
  });
  
  // Обработка отключения
  socket.on('disconnect', () => {
    console.log('📴 WebSocket disconnected:', socket.username);
    
    io.emit('userStatus', {
      userId: socket.userId,
      username: socket.username,
      status: 'offline'
    });
  });
});

// ============================================
// ЗАПУСК СЕРВЕРА
// ============================================
server.listen(port, () => {
  console.log(`🚀 KGram Server running on port ${port}`);
  console.log(`🌐 Health: http://localhost:${port}/health`);
  console.log(`📡 API: http://localhost:${port}/api`);
  console.log(`🔌 WebSocket: ws://localhost:${port}/chat`);
});

// Обработка ошибок
process.on('uncaughtException', (err) => {
  console.error('❌ Uncaught Exception:', err);
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('❌ Unhandled Rejection:', reason);
});
