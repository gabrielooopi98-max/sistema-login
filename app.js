require('dotenv').config();
const express = require('express');
const session = require('express-session');
const pgSession = require('connect-pg-simple')(session);
const path = require('path');

const pool = require('./config/db');
const authRoutes = require('./routes/auth');
const { requireAuth } = require('./middleware/auth');

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Sessão guardada no próprio PostgreSQL (tabela "session" criada pelo schema.sql)
app.use(
  session({
    store: new pgSession({
      pool,
      tableName: 'session',
    }),
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      maxAge: 1000 * 60 * 60 * 24 * 7, // 7 dias
    },
  })
);

// Rotas de autenticação (register, login, logout, me)
app.use('/api/auth', authRoutes);

// Exemplo de rota protegida (só acessível logado)
app.get('/api/dashboard', requireAuth, (req, res) => {
  res.json({ message: `Bem-vindo! Você está logado com o id de sessão ${req.session.userId}.` });
});

// Serve os arquivos estáticos (páginas de login/registro)
app.use(express.static(path.join(__dirname, 'public')));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Servidor rodando em http://localhost:${PORT}`);
});