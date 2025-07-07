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

// 🔐 Middleware: sprawdzanie tokenu
function authMiddleware(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth?.startsWith('Bearer ')) return res.status(401).json({ error: 'Brak tokena' });

  const token = auth.split(' ')[1];
  try {
    const data = jwt.verify(token, process.env.JWT_SECRET);
    req.user = data;
    next();
  } catch (e) {
    res.status(401).json({ error: 'Token nieprawidłowy' });
  }
}

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
app.get('/auth/me', authMiddleware, (req, res) => {
  res.json({ id: req.user.id, role: req.user.role });
});


// 📦 Tworzenie zlecenia
app.post('/orders', authMiddleware, async (req, res) => {
  if (!['tworzy_zlecenia', 'admin'].includes(req.user.role)) {
    return res.status(403).json({ error: 'Brak uprawnień do tworzenia zleceń' });
  }

  const { invoice, carrier, client_name, purchase_date, items } = req.body;

  if (!items || !Array.isArray(items) || items.length === 0) {
    return res.status(400).json({ error: 'Brak pozycji produktowych' });
  }

  try {
    const [existingOrders] = await db.query('SELECT COUNT(*) as count FROM orders');
    const nextNumber = existingOrders[0].count + 1;
    const orderNumber = `ZL-${nextNumber.toString().padStart(5, '0')}`;

    const [result] = await db.query(
      `INSERT INTO orders (order_number, invoice, carrier, client_name, purchase_date)
      VALUES (?, ?, ?, ?, ?)`,
      [orderNumber, invoice, carrier, client_name, purchase_date || null]
    );

    const orderId = result.insertId;

    for (const item of items) {
      const { product_name, quantity, info } = item;
      if (!product_name || !quantity) continue;
      await db.query(
        `INSERT INTO order_items (order_id, product_name, quantity, info)
         VALUES (?, ?, ?, ?)`,
        [orderId, product_name, quantity, info || '']
      );
    }

    res.json({ success: true, message: 'Zlecenie utworzone', order_number: orderNumber });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


// 📋 Lista zleceń do wykonania (z produktami)
app.get('/orders/queue', authMiddleware, async (req, res) => {
  try {
    // Pobierz zlecenia wraz z loginem przypisanego pracownika
    const [orders] = await db.query(`
      SELECT orders.*, users.username AS assigned_username
      FROM orders
      LEFT JOIN users ON orders.assigned_to = users.id
      WHERE orders.status IN ('new', 'taken')
      ORDER BY orders.created_at DESC
    `);

    // Dla każdego zlecenia pobierz produkty (items)
    for (const order of orders) {
      const [items] = await db.query(
        'SELECT product_name, quantity, info FROM order_items WHERE order_id = ?',
        [order.id]
      );
      order.items = items;
    }

    res.json(orders);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


// 🧍 Przypisanie zlecenia do siebie
app.post('/orders/take/:id', authMiddleware, async (req, res) => {
  const orderId = req.params.id;
  try {
    await db.query(
      'UPDATE orders SET status = "taken", assigned_to = ? WHERE id = ? AND status = "new"',
      [req.user.id, orderId]
    );
    res.json({ success: true, message: 'Zlecenie przypisane' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 📋 Lista moich zleceń do wykonania (z produktami)
app.get('/orders/my', authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id;

    // Pobierz zlecenia przypisane do użytkownika
    const [orders] = await db.query(
      'SELECT * FROM orders WHERE assigned_to = ? ORDER BY created_at DESC',
      [userId]
    );

    // Dołącz produkty (items) do każdego zlecenia
    for (const order of orders) {
      const [items] = await db.query(
        'SELECT product_name, quantity, info FROM order_items WHERE order_id = ?',
        [order.id]
      );
      order.items = items;
    }

    res.json(orders);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ✅ Zakończenie zlecenia
app.post('/orders/finish/:id', authMiddleware, async (req, res) => {
  const orderId = req.params.id;
  const { serial_numbers } = req.body;

  if (!Array.isArray(serial_numbers)) {
    return res.status(400).json({ error: 'serial_numbers musi być tablicą' });
  }

  try {
    await db.query(
      `UPDATE orders
       SET status = "done", serial_numbers = ?
       WHERE id = ? AND assigned_to = ?`,
      [JSON.stringify(serial_numbers), orderId, req.user.id]
    );
    res.json({ success: true, message: 'Zlecenie zakończone' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Serwer działa na porcie ${PORT}`);
});

// ✅ Zwolnij zlecenie
app.post('/orders/release/:id', authMiddleware, async (req, res) => {
  const userId = req.user.id;
  const orderId = req.params.id;

  try {
    // upewnij się, że to zlecenie należy do tego użytkownika
    const [orders] = await db.query('SELECT * FROM orders WHERE id = ?', [orderId]);
    if (!orders.length || orders[0].assigned_to !== userId) {
      return res.status(403).json({ error: 'Nie możesz zwolnić tego zlecenia' });
    }

    await db.query('UPDATE orders SET assigned_to = NULL, status = "new" WHERE id = ?', [orderId]);
    res.json({ success: true, message: 'Zlecenie zwolnione' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

