const express = require('express');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();
const db = new Database('bank.db');
const JWT_SECRET = 'experimental-banking-secret-key-12345';

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Initialize Database Schema
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT,
    account_number TEXT UNIQUE,
    balance REAL DEFAULT 1000.00
  );

  CREATE TABLE IF NOT EXISTS transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    account_number TEXT,
    type TEXT,
    amount REAL,
    recipient_account TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`);

// Middleware: Authenticate JWT Token
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access token required' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid or expired token' });
    req.user = user;
    next();
  });
}

// 1. User Registration
app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const accountNumber = 'ACCT' + Math.floor(10000000 + Math.random() * 90000000);

    const stmt = db.prepare('INSERT INTO users (username, password, account_number) VALUES (?, ?, ?)');
    stmt.run(username, hashedPassword, accountNumber);

    res.json({ message: 'Account created successfully!', accountNumber });
  } catch (err) {
    res.status(400).json({ error: 'Username already exists' });
  }
});

// 2. User Login
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);

  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(400).json({ error: 'Invalid credentials' });
  }

  const token = jwt.sign({ id: user.id, username: user.username, accountNumber: user.account_number }, JWT_SECRET, { expiresIn: '1h' });
  res.json({ token, username: user.username, accountNumber: user.account_number });
});

// 3. Get Account Dashboard Data
app.get('/api/account', authenticateToken, (req, res) => {
  const user = db.prepare('SELECT id, username, account_number, balance FROM users WHERE id = ?').get(req.user.id);
  const transactions = db.prepare('SELECT * FROM transactions WHERE account_number = ? ORDER BY timestamp DESC LIMIT 10').all(user.account_number);

  res.json({ user, transactions });
});

// 4. Transfer Funds (Transactional)
app.post('/api/transfer', authenticateToken, (req, res) => {
  const { recipientAccount, amount } = req.body;
  const transferAmount = parseFloat(amount);

  if (!recipientAccount || isNaN(transferAmount) || transferAmount <= 0) {
    return res.status(400).json({ error: 'Invalid recipient or amount' });
  }

  const sender = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  if (sender.balance < transferAmount) {
    return res.status(400).json({ error: 'Insufficient funds' });
  }

  const recipient = db.prepare('SELECT * FROM users WHERE account_number = ?').get(recipientAccount);
  if (!recipient) {
    return res.status(404).json({ error: 'Recipient account not found' });
  }

  // Transaction SQL Execution
  const executeTransfer = db.transaction(() => {
    db.prepare('UPDATE users SET balance = balance - ? WHERE id = ?').run(transferAmount, sender.id);
    db.prepare('UPDATE users SET balance = balance + ? WHERE account_number = ?').run(transferAmount, recipientAccount);

    db.prepare('INSERT INTO transactions (account_number, type, amount, recipient_account) VALUES (?, ?, ?, ?)').run(
      sender.account_number, 'DEBIT', transferAmount, recipientAccount
    );
    db.prepare('INSERT INTO transactions (account_number, type, amount, recipient_account) VALUES (?, ?, ?, ?)').run(
      recipientAccount, 'CREDIT', transferAmount, sender.account_number
    );
  });

  try {
    executeTransfer();
    res.json({ message: 'Transfer successful!' });
  } catch (err) {
    res.status(500).json({ error: 'Transaction failed' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Online Banking Prototype running on http://localhost:${PORT}`));