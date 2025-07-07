const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const db = require('./models/db');

dotenv.config();
const app = express();

app.use(cors());
app.use(express.json());

// 🔹 Test: sprawdzenie czy serwer działa
app.get('/', (req, res) => {
  res.send('Serwer działa!');
});

// 🔐 Rejestracja użytkownika
app.post('/auth/register', async (req, res) => {
  const { username, password, role } = req.body;
  if (!username || !password || !role) {
    return res.status(400).json({ error: 'Brakuje wymaganych pól' });
  }

  try {
    const hash = await bcrypt.hash(password, 10);
    await db.query(
      'INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)',
      [username, hash, role]
    );
    res.json({ success: true, message: 'Użytkownik zarejestrowany' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 🔐 Logowanie użytkownika
app.post('/auth/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    const [rows] = await db.query('SELECT * FROM users WHERE username = ?', [username]);
    const user = rows[0];

    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).json({ error: 'Zły login lub hasło' });
    }

    const token = jwt.sign(
      { id: user.id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '12h' }
    );
    res.json({ token });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 🔐 Sprawdzenie tokena JWT
app.get('/auth/me', (req, res) => {
  const auth = req.head
