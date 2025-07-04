require('dotenv').config();
const express = require('express');
const cors = require('cors');
const db = require('./models/db');

const app = express(); // ✅ utworzenie app

app.use(cors());
app.use(express.json());

app.get('/', (req, res) => {
  res.send('Serwer działa!');
});

app.get('/test-db', async (req, res) => {
  try {
    const [rows] = await db.query('SELECT NOW() AS now');
    res.json({ success: true, now: rows[0].now });
  } catch (error) {
    console.error('Błąd bazy danych:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Serwer działa na porcie ${PORT}`);
});
