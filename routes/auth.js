const express = require('express');
const bcrypt = require('bcrypt');
const { body, validationResult } = require('express-validator');
const pool = require('../config/db');
const { requireAuth } = require('../middleware/auth');

const router = express.Router();
const SALT_ROUNDS = 12;

// ---------- REGISTRO ----------
router.post(
  '/register',
  [
    body('name').trim().notEmpty().withMessage('Nome é obrigatório.'),
    body('email').isEmail().withMessage('E-mail inválido.').normalizeEmail(),
    body('password')
      .isLength({ min: 8 })
      .withMessage('A senha precisa ter no mínimo 8 caracteres.'),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { name, email, password } = req.body;

    try {
      const existing = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
      if (existing.rows.length > 0) {
        return res.status(409).json({ error: 'Já existe uma conta com esse e-mail.' });
      }

      const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);

      const result = await pool.query(
        'INSERT INTO users (name, email, password_hash) VALUES ($1, $2, $3) RETURNING id, name, email',
        [name, email, passwordHash]
      );

      const user = result.rows[0];
      req.session.userId = user.id;

      return res.status(201).json({ message: 'Conta criada com sucesso!', user });
    } catch (err) {
      console.error('Erro no registro:', err);
      return res.status(500).json({ error: 'Erro interno ao criar conta.' });
    }
  }
);

// ---------- LOGIN ----------
router.post(
  '/login',
  [
    body('email').isEmail().withMessage('E-mail inválido.').normalizeEmail(),
    body('password').notEmpty().withMessage('Senha é obrigatória.'),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { email, password } = req.body;

    try {
      const result = await pool.query(
        'SELECT id, name, email, password_hash FROM users WHERE email = $1',
        [email]
      );

      const genericError = { error: 'E-mail ou senha inválidos.' };

      if (result.rows.length === 0) {
        return res.status(401).json(genericError);
      }

      const user = result.rows[0];
      const passwordMatches = await bcrypt.compare(password, user.password_hash);

      if (!passwordMatches) {
        return res.status(401).json(genericError);
      }

      req.session.regenerate((err) => {
        if (err) {
          console.error('Erro ao regenerar sessão:', err);
          return res.status(500).json({ error: 'Erro interno ao logar.' });
        }

        req.session.userId = user.id;
        return res.json({
          message: 'Login realizado com sucesso!',
          user: { id: user.id, name: user.name, email: user.email },
        });
      });
    } catch (err) {
      console.error('Erro no login:', err);
      return res.status(500).json({ error: 'Erro interno ao logar.' });
    }
  }
);

// ---------- LOGOUT ----------
router.post('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error('Erro ao destruir sessão:', err);
      return res.status(500).json({ error: 'Erro ao sair.' });
    }
    res.clearCookie('connect.sid');
    return res.json({ message: 'Logout realizado com sucesso.' });
  });
});

// ---------- USUÁRIO LOGADO ----------
router.get('/me', requireAuth, async (req, res) => {
  try {
    const result = await pool.query('SELECT id, name, email, created_at FROM users WHERE id = $1', [
      req.session.userId,
    ]);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Usuário não encontrado.' });
    }

    return res.json({ user: result.rows[0] });
  } catch (err) {
    console.error('Erro ao buscar usuário:', err);
    return res.status(500).json({ error: 'Erro interno.' });
  }
});

module.exports = router;