const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const app = express();
const port = 3000;
const SECRET_KEY = 'your-secret-key'; // Replace with a secure key in production

// Configure nodemailer
const transporter = nodemailer.createTransport({
  host: 'smtp.gmail.com',
  port: 587,
  secure: false,
  auth: {
    user: 'algotrading089@gmail.com',
    pass: 'kvct wlkq ctmc xzzg' // App Password for Gmail
  }
});

app.use(cors());
app.use(express.json());
app.use(express.static('public'));

const db = new sqlite3.Database('./expenses.db', (err) => {
  if (err) {
    console.error('Error opening database:', err.message);
    return;
  }
  console.log('Connected to SQLite database.');

  db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      verified INTEGER DEFAULT 0
    )`, (err) => {
      if (err) console.error('Error creating users table:', err.message);
      else console.log('Users table created or exists.');
    });

    db.run(`CREATE TABLE IF NOT EXISTS user_profiles (
      user_id INTEGER PRIMARY KEY,
      name TEXT,
      gender TEXT,
      dob TEXT,
      FOREIGN KEY(user_id) REFERENCES users(id)
    )`, (err) => {
      if (err) console.error('Error creating user_profiles table:', err.message);
      else console.log('User_profiles table created or exists.');
    });

    db.run(`CREATE TABLE IF NOT EXISTS verification_codes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT NOT NULL,
      code TEXT NOT NULL,
      type TEXT NOT NULL,
      expires_at INTEGER NOT NULL
    )`, (err) => {
      if (err) console.error('Error creating verification_codes table:', err.message);
      else console.log('Verification_codes table created or exists.');
    });

    db.run(`CREATE TABLE IF NOT EXISTS categories (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      name TEXT NOT NULL,
      deleted INTEGER DEFAULT 0,
      UNIQUE(user_id, name),
      FOREIGN KEY(user_id) REFERENCES users(id)
    )`, (err) => {
      if (err) console.error('Error creating categories table:', err.message);
      else console.log('Categories table created or exists.');
    });

    db.run(`CREATE TABLE IF NOT EXISTS expenses (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      date TEXT NOT NULL,
      category_id INTEGER,
      amount DECIMAL(10,2),
      deleted INTEGER DEFAULT 0,
      FOREIGN KEY(user_id) REFERENCES users(id),
      FOREIGN KEY(category_id) REFERENCES categories(id)
    )`, (err) => {
      if (err) console.error('Error creating expenses table:', err.message);
      else console.log('Expenses table created or exists.');
    });
  });
});

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access token required' });

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid or expired token' });
    req.user = user;
    next();
  });
};

const generateVerificationCode = () => {
  return Math.floor(100000 + Math.random() * 900000).toString();
};

const generateRandomPassword = () => {
  return crypto.randomBytes(8).toString('base64').slice(0, 12)
    .replace(/[^a-zA-Z0-9]/g, '')
    + Math.floor(Math.random() * 100);
};

const sendVerificationEmail = async (email, code, type) => {
  const subject = type === 'register' ? 'Verify Your Email' : 'Password Reset Code';
  const text = `Your verification code is: ${code}. It expires in 10 minutes.`;
  try {
    await transporter.sendMail({
      from: '"Visionary Infra" <algotrading089@gmail.com>',
      to: email,
      subject,
      text,
      html: `<p>Your verification code is: <strong>${code}</strong>. It expires in 10 minutes.</p>`
    });
    console.log(`Verification email sent to ${email}`);
  } catch (e) {
    console.error('Email sending error:', e);
    throw new Error('Failed to send verification email');
  }
};

const sendNewPasswordEmail = async (email, password) => {
  const subject = 'Your New Password';
  const text = `Your new password is: ${password}. Use it to log in and update it in your profile.`;
  try {
    await transporter.sendMail({
      from: '"Visionary Infra" <algotrading089@gmail.com>',
      to: email,
      subject,
      text,
      html: `<p>Your new password is: <strong>${password}</strong>. Use it to log in and update it in your profile.</p>`
    });
    console.log(`New password sent to ${email}`);
  } catch (e) {
    console.error('Email sending error:', e);
    throw new Error('Failed to send password email');
  }
};

app.post('/send-verification-code', async (req, res) => {
  const { email, type } = req.body;
  if (!email || !type || !['register', 'reset'].includes(type)) {
    return res.status(400).json({ error: 'Valid email and type (register/reset) required' });
  }
  try {
    if (type === 'reset') {
      const user = await new Promise((resolve, reject) => {
        db.get('SELECT * FROM users WHERE email = ?', [email], (err, row) => {
          if (err) reject(err);
          resolve(row);
        });
      });
      if (!user) {
        return res.status(400).json({ error: 'Account not registered' });
      }
    }
    const code = generateVerificationCode();
    const expiresAt = Date.now() + 10 * 60 * 1000; // 10 minutes
    await new Promise((resolve, reject) => {
      db.run(
        'INSERT INTO verification_codes (email, code, type, expires_at) VALUES (?, ?, ?, ?)',
        [email, code, type, expiresAt],
        (err) => {
          if (err) reject(err);
          resolve();
        }
      );
    });
    await sendVerificationEmail(email, code, type);
    res.json({ message: 'Verification code sent' });
  } catch (e) {
    console.error('Send verification code error:', e);
    res.status(500).json({ error: 'Failed to send verification code' });
  }
});

app.post('/verify-code', async (req, res) => {
  const { email, code, type } = req.body;
  if (!email || !code || !type) {
    return res.status(400).json({ error: 'Email, code, and type required' });
  }
  try {
    const row = await new Promise((resolve, reject) => {
      db.get(
        'SELECT * FROM verification_codes WHERE email = ? AND code = ? AND type = ? AND expires_at > ?',
        [email, code, type, Date.now()],
        (err, row) => {
          if (err) reject(err);
          resolve(row);
        }
      );
    });
    if (!row) {
      return res.status(400).json({ error: 'Invalid or expired code' });
    }
    await new Promise((resolve, reject) => {
      db.run('DELETE FROM verification_codes WHERE id = ?', [row.id], (err) => {
        if (err) reject(err);
        resolve();
      });
    });
    res.json({ message: 'Code verified' });
  } catch (e) {
    console.error('Verify code error:', e);
    res.status(500).json({ error: 'Failed to verify code' });
  }
});

app.post('/register', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password required' });
  }
  try {
    const existingUser = await new Promise((resolve, reject) => {
      db.get('SELECT * FROM users WHERE email = ?', [email], (err, row) => {
        if (err) reject(err);
        resolve(row);
      });
    });
    if (existingUser) {
      if (existingUser.verified) {
        return res.status(400).json({ error: 'Email already exists' });
      } else {
        // Delete unverified user and associated verification codes
        await new Promise((resolve, reject) => {
          db.run('DELETE FROM verification_codes WHERE email = ?', [email], (err) => {
            if (err) reject(err);
            resolve();
          });
        });
        await new Promise((resolve, reject) => {
          db.run('DELETE FROM users WHERE email = ?', [email], (err) => {
            if (err) reject(err);
            resolve();
          });
        });
      }
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const code = generateVerificationCode();
    const expiresAt = Date.now() + 10 * 60 * 1000; // 10 minutes
    await new Promise((resolve, reject) => {
      db.run(
        'INSERT INTO users (email, password, verified) VALUES (?, ?, 0)',
        [email, hashedPassword],
        (err) => {
          if (err) reject(err);
          resolve();
        }
      );
    });
    await new Promise((resolve, reject) => {
      db.run(
        'INSERT INTO verification_codes (email, code, type, expires_at) VALUES (?, ?, ?, ?)',
        [email, code, 'register', expiresAt],
        (err) => {
          if (err) reject(err);
          resolve();
        }
      );
    });
    await sendVerificationEmail(email, code, 'register');
    res.json({ message: 'Verification code sent' });
  } catch (e) {
    console.error('Register error:', e);
    res.status(500).json({ error: 'Failed to register user' });
  }
});

app.post('/verify', async (req, res) => {
  const { email, code } = req.body;
  if (!email || !code) {
    return res.status(400).json({ error: 'Email and code required' });
  }
  try {
    const verification = await new Promise((resolve, reject) => {
      db.get(
        'SELECT * FROM verification_codes WHERE email = ? AND code = ? AND type = ? AND expires_at > ?',
        [email, code, 'register', Date.now()],
        (err, row) => {
          if (err) reject(err);
          resolve(row);
        }
      );
    });
    if (!verification) {
      return res.status(400).json({ error: 'Invalid or expired verification code' });
    }
    const updateResult = await new Promise((resolve, reject) => {
      db.run(
        'UPDATE users SET verified = 1 WHERE email = ?',
        [email],
        function(err) {
          if (err) reject(err);
          resolve(this.changes);
        }
      );
    });
    if (updateResult === 0) {
      return res.status(400).json({ error: 'User not found' });
    }
    await new Promise((resolve, reject) => {
      db.run('DELETE FROM verification_codes WHERE email = ? AND type = ?', [email, 'register'], (err) => {
        if (err) reject(err);
        resolve();
      });
    });
    const user = await new Promise((resolve, reject) => {
      db.get('SELECT id, email FROM users WHERE email = ?', [email], (err, row) => {
        if (err) reject(err);
        resolve(row);
      });
    });
    const token = jwt.sign({ id: user.id, email: user.email }, SECRET_KEY, { expiresIn: '1h' });
    const defaultCategories = [
      'Food', 'Salaries', 'Vehicle payment', 'Department expenses',
      'Gravel', 'Cement', 'Metal', 'Labour', 'Diesel', 'Remarks', 'Project expenses'
    ];
    await Promise.all(defaultCategories.map(category => new Promise((resolve, reject) => {
      db.run(
        'INSERT OR IGNORE INTO categories (user_id, name) VALUES (?, ?)',
        [user.id, category],
        (err) => {
          if (err) reject(err);
          resolve();
        }
      );
    })));
    res.json({ message: 'Email verified successfully', token });
  } catch (e) {
    console.error('Verify error:', e);
    res.status(500).json({ error: 'Failed to verify email' });
  }
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password required' });
  }
  try {
    const user = await new Promise((resolve, reject) => {
      db.get('SELECT * FROM users WHERE email = ?', [email], (err, row) => {
        if (err) reject(err);
        resolve(row);
      });
    });
    if (!user) {
      return res.status(401).json({ error: 'Account not registered' });
    }
    if (!user.verified) {
      return res.status(403).json({ error: 'Email not verified' });
    }
    if (!(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: 'Invalid password' });
    }
    const token = jwt.sign({ id: user.id, email: user.email }, SECRET_KEY, { expiresIn: '1h' });
    res.json({ token });
  } catch (e) {
    console.error('Login error:', e);
    res.status(500).json({ error: 'Failed to login' });
  }
});

app.post('/forgot-password', async (req, res) => {
  const { email } = req.body;
  if (!email) {
    return res.status(400).json({ error: 'Email required' });
  }
  try {
    const user = await new Promise((resolve, reject) => {
      db.get('SELECT id, email FROM users WHERE email = ?', [email], (err, row) => {
        if (err) reject(err);
        resolve(row);
      });
    });
    if (!user) {
      return res.status(400).json({ error: 'Account not registered' });
    }
    const newPassword = generateRandomPassword();
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await new Promise((resolve, reject) => {
      db.run(
        'UPDATE users SET password = ? WHERE email = ?',
        [hashedPassword, email],
        (err) => {
          if (err) reject(err);
          resolve();
        }
      );
    });
    await sendNewPasswordEmail(email, newPassword);
    res.json({ message: 'New password sent to your email' });
  } catch (e) {
    console.error('Forgot password error:', e);
    res.status(500).json({ error: 'Failed to process password reset' });
  }
});

app.get('/profile', authenticateToken, async (req, res) => {
  try {
    const row = await new Promise((resolve, reject) => {
      db.get('SELECT name, gender, dob FROM user_profiles WHERE user_id = ?', [req.user.id], (err, row) => {
        if (err) reject(err);
        resolve(row);
      });
    });
    res.json(row || {});
  } catch (e) {
    console.error('Fetch profile error:', e);
    res.status(500).json({ error: 'Failed to fetch profile' });
  }
});

app.post('/profile', authenticateToken, async (req, res) => {
  const { name, gender, dob } = req.body;
  try {
    const row = await new Promise((resolve, reject) => {
      db.get('SELECT user_id FROM user_profiles WHERE user_id = ?', [req.user.id], (err, row) => {
        if (err) reject(err);
        resolve(row);
      });
    });
    if (row) {
      await new Promise((resolve, reject) => {
        db.run(
          'UPDATE user_profiles SET name = ?, gender = ?, dob = ? WHERE user_id = ?',
          [name || null, gender || null, dob || null, req.user.id],
          (err) => {
            if (err) reject(err);
            resolve();
          }
        );
      });
      res.json({ message: 'Profile updated successfully' });
    } else {
      await new Promise((resolve, reject) => {
        db.run(
          'INSERT INTO user_profiles (user_id, name, gender, dob) VALUES (?, ?, ?, ?)',
          [req.user.id, name || null, gender || null, dob || null],
          (err) => {
            if (err) reject(err);
            resolve();
          }
        );
      });
      res.json({ message: 'Profile saved successfully' });
    }
  } catch (e) {
    console.error('Profile error:', e);
    res.status(500).json({ error: 'Failed to save profile' });
  }
});

app.post('/update-password', authenticateToken, async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  if (!currentPassword || !newPassword) {
    return res.status(400).json({ error: 'Current and new password required' });
  }
  try {
    const user = await new Promise((resolve, reject) => {
      db.get('SELECT password FROM users WHERE id = ?', [req.user.id], (err, row) => {
        if (err) reject(err);
        resolve(row);
      });
    });
    if (!user || !(await bcrypt.compare(currentPassword, user.password))) {
      return res.status(401).json({ error: 'Invalid current password' });
    }
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await new Promise((resolve, reject) => {
      db.run('UPDATE users SET password = ? WHERE id = ?', [hashedPassword, req.user.id], (err) => {
        if (err) reject(err);
        resolve();
      });
    });
    res.json({ message: 'Password updated successfully' });
  } catch (e) {
    console.error('Update password error:', e);
    res.status(500).json({ error: 'Failed to update password' });
  }
});

app.get('/categories', authenticateToken, async (req, res) => {
  try {
    const rows = await new Promise((resolve, reject) => {
      db.all('SELECT * FROM categories WHERE user_id = ? AND deleted = 0', [req.user.id], (err, rows) => {
        if (err) reject(err);
        resolve(rows);
      });
    });
    res.json(rows);
  } catch (e) {
    console.error('Fetch categories error:', e);
    res.status(500).json({ error: 'Failed to fetch categories' });
  }
});

app.post('/categories', authenticateToken, async (req, res) => {
  const { name } = req.body;
  if (!name) return res.status(400).json({ error: 'Category name required' });
  try {
    const row = await new Promise((resolve, reject) => {
      db.get('SELECT id, deleted FROM categories WHERE user_id = ? AND name = ?', [req.user.id, name], (err, row) => {
        if (err) reject(err);
        resolve(row);
      });
    });
    if (row) {
      if (row.deleted) {
        await new Promise((resolve, reject) => {
          db.run('UPDATE categories SET deleted = 0 WHERE id = ?', [row.id], (err) => {
            if (err) reject(err);
            resolve();
          });
        });
        res.json({ id: row.id, name });
      } else {
        return res.status(400).json({ error: 'Category already exists' });
      }
    } else {
      const result = await new Promise((resolve, reject) => {
        db.run('INSERT INTO categories (user_id, name) VALUES (?, ?)', [req.user.id, name], function(err) {
          if (err) reject(err);
          resolve(this.lastID);
        });
      });
      res.json({ id: result, name });
    }
  } catch (e) {
    console.error('Insert category error:', e);
    res.status(500).json({ error: 'Failed to add category' });
  }
});

app.delete('/categories/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  try {
    await new Promise((resolve, reject) => {
      db.run('UPDATE expenses SET deleted = 1 WHERE user_id = ? AND category_id = ?', [req.user.id, id], (err) => {
        if (err) reject(err);
        resolve();
      });
    });
    await new Promise((resolve, reject) => {
      db.run('UPDATE categories SET deleted = 1 WHERE id = ? AND user_id = ?', [id, req.user.id], (err) => {
        if (err) reject(err);
        resolve();
      });
    });
    res.json({ message: 'Category deleted successfully', categoryId: id });
  } catch (e) {
    console.error('Delete category error:', e);
    res.status(500).json({ error: 'Failed to delete category' });
  }
});

app.get('/expenses', authenticateToken, async (req, res) => {
  try {
    const rows = await new Promise((resolve, reject) => {
      db.all(`
        SELECT e.date, c.name as category, e.amount
        FROM expenses e
        JOIN categories c ON e.category_id = c.id
        WHERE e.user_id = ? AND e.deleted = 0 AND c.deleted = 0
        ORDER BY e.date DESC
      `, [req.user.id], (err, rows) => {
        if (err) reject(err);
        resolve(rows);
      });
    });
    const expensesByDate = rows.reduce((acc, row) => {
      if (!acc[row.date]) acc[row.date] = { date: row.date, amounts: {} };
      acc[row.date].amounts[row.category] = row.amount.toFixed(2);
      return acc;
    }, {});
    res.json(Object.values(expensesByDate));
  } catch (e) {
    console.error('Fetch expenses error:', e);
    res.status(500).json({ error: 'Failed to fetch expenses' });
  }
});

app.post('/expenses', authenticateToken, async (req, res) => {
  const { date, amounts } = req.body;
  if (!date || !amounts) return res.status(400).json({ error: 'Date and amounts required' });
  try {
    await new Promise((resolve, reject) => db.run('BEGIN TRANSACTION', (err) => err ? reject(err) : resolve()));
    const errors = [];
    const categories = Object.keys(amounts);
    await Promise.all(categories.map(async (category) => {
      const amount = parseFloat(amounts[category]);
      if (!amount || amount <= 0) return;
      const row = await new Promise((resolve, reject) => {
        db.get('SELECT id FROM categories WHERE user_id = ? AND name = ? AND deleted = 0', [req.user.id, category], (err, row) => {
          if (err) reject(err);
          resolve(row);
        });
      });
      if (row) {
        await new Promise((resolve, reject) => {
          db.run(
            'INSERT INTO expenses (user_id, date, category_id, amount) VALUES (?, ?, ?, ?)',
            [req.user.id, date, row.id, amount],
            (err) => {
              if (err) {
                errors.push(`Error saving expense for ${category}: ${err.message}`);
                resolve();
              } else {
                resolve();
              }
            }
          );
        });
      } else {
        errors.push(`Category ${category} not found`);
      }
    }));
    await new Promise((resolve, reject) => db.run('COMMIT', (err) => err ? reject(err) : resolve()));
    res.json({ message: 'Expenses saved', errors });
  } catch (e) {
    await new Promise((resolve) => db.run('ROLLBACK', () => resolve()));
    console.error('Insert expenses error:', e);
    res.status(500).json({ error: 'Failed to save expenses' });
  }
});

app.post('/expenses/import', authenticateToken, async (req, res) => {
  const { data } = req.body;
  if (!Array.isArray(data) || !data.length) {
    return res.status(400).json({ error: 'Invalid or empty data' });
  }
  try {
    await new Promise((resolve, reject) => db.run('BEGIN TRANSACTION', (err) => err ? reject(err) : resolve()));
    const errors = [];
    for (const [index, { date, amounts }] of data.entries()) {
      if (!date || !amounts || !Object.keys(amounts).length) {
        errors.push(`Row ${index + 1}: Invalid date or amounts`);
        continue;
      }
      const categories = Object.keys(amounts);
      for (const category of categories) {
        const amount = parseFloat(amounts[category]);
        if (!amount || amount <= 0) continue;
        let row = await new Promise((resolve, reject) => {
          db.get('SELECT id, deleted FROM categories WHERE user_id = ? AND name = ?', [req.user.id, category], (err, row) => {
            if (err) reject(err);
            resolve(row);
          });
        });
        let catId;
        if (row) {
          if (row.deleted) {
            await new Promise((resolve, reject) => {
              db.run('UPDATE categories SET deleted = 0 WHERE id = ?', [row.id], (err) => {
                if (err) reject(err);
                resolve();
              });
            });
            catId = row.id;
          } else {
            catId = row.id;
          }
        } else {
          catId = await new Promise((resolve, reject) => {
            db.run('INSERT INTO categories (user_id, name) VALUES (?, ?)', [req.user.id, category], function(err) {
              if (err) reject(err);
              resolve(this.lastID);
            });
          });
        }
        const existing = await new Promise((resolve, reject) => {
          db.get(
            'SELECT id, amount FROM expenses WHERE user_id = ? AND date = ? AND category_id = ? AND deleted = 0',
            [req.user.id, date, catId],
            (err, row) => {
              if (err) reject(err);
              resolve(row);
            }
          );
        });
        if (existing) {
          const newAmount = parseFloat(existing.amount) + amount;
          await new Promise((resolve, reject) => {
            db.run(
              'UPDATE expenses SET amount = ? WHERE id = ?',
              [newAmount, existing.id],
              (err) => {
                if (err) {
                  errors.push(`Row ${index + 1}, ${category}: Failed to update expense: ${err.message}`);
                  resolve();
                } else {
                  resolve();
                }
              }
            );
          });
        } else {
          await new Promise((resolve, reject) => {
            db.run(
              'INSERT INTO expenses (user_id, date, category_id, amount) VALUES (?, ?, ?, ?)',
              [req.user.id, date, catId, amount],
              (err) => {
                if (err) {
                  errors.push(`Row ${index + 1}, ${category}: Failed to insert expense: ${err.message}`);
                  resolve();
                } else {
                  resolve();
                }
              }
            );
          });
        }
      }
    }
    await new Promise((resolve, reject) => db.run('COMMIT', (err) => err ? reject(err) : resolve()));
    if (errors.length) {
      res.status(400).json({ message: 'Import completed with errors', errors });
    } else {
      res.json({ message: 'Expenses imported successfully' });
    }
  } catch (e) {
    await new Promise((resolve) => db.run('ROLLBACK', () => resolve()));
    console.error('Import expenses error:', e);
    res.status(500).json({ error: 'Failed to import expenses' });
  }
});

app.delete('/expenses/:date/:category', authenticateToken, async (req, res) => {
  const { date, category } = req.params;
  try {
    const row = await new Promise((resolve, reject) => {
      db.get('SELECT id FROM categories WHERE user_id = ? AND name = ? AND deleted = 0', [req.user.id, category], (err, row) => {
        if (err) reject(err);
        resolve(row);
      });
    });
    if (!row) {
      return res.status(400).json({ error: 'Category not found' });
    }
    await new Promise((resolve, reject) => {
      db.run(
        'UPDATE expenses SET deleted = 1 WHERE user_id = ? AND date = ? AND category_id = ? AND deleted = 0',
        [req.user.id, date, row.id],
        (err) => {
          if (err) reject(err);
          resolve();
        }
      );
    });
    res.json({ message: 'Expense deleted successfully', date, category });
  } catch (e) {
    console.error('Delete expense error:', e);
    res.status(500).json({ error: 'Failed to delete expense' });
  }
});

app.get('/stats', authenticateToken, async (req, res) => {
  const { fromDate, toDate } = req.query;
  let query = `
    SELECT c.name as category, SUM(e.amount) as total
    FROM expenses e
    JOIN categories c ON e.category_id = c.id
    WHERE e.user_id = ? AND e.deleted = 0 AND c.deleted = 0
  `;
  const params = [req.user.id];
  if (fromDate && toDate) {
    query += ' AND e.date BETWEEN ? AND ?';
    params.push(fromDate, toDate);
  }
  query += ' GROUP BY c.name';
  try {
    const rows = await new Promise((resolve, reject) => {
      db.all(query, params, (err, rows) => {
        if (err) reject(err);
        resolve(rows);
      });
    });
    const total = rows.reduce((sum, row) => sum + row.total, 0);
    const stats = {
      total,
      byCategory: rows.reduce((acc, row) => {
        acc[row.category] = row.total;
        return acc;
      }, {}),
      percentages: rows.reduce((acc, row) => {
        acc[row.category] = total ? ((row.total / total) * 100).toFixed(2) : 0;
        return acc;
      }, {})
    };
    res.json(stats);
  } catch (e) {
    console.error('Fetch stats error:', e);
    res.status(500).json({ error: 'Failed to fetch stats' });
  }
});

app.get('/stats/top', authenticateToken, async (req, res) => {
  const { fromDate, toDate } = req.query;
  let query = `
    SELECT c.name as category, SUM(e.amount) as total
    FROM expenses e
    JOIN categories c ON e.category_id = c.id
    WHERE e.user_id = ? AND e.deleted = 0 AND c.deleted = 0
  `;
  const params = [req.user.id];
  if (fromDate && toDate) {
    query += ' AND e.date BETWEEN ? AND ?';
    params.push(fromDate, toDate);
  }
  query += ' GROUP BY c.name ORDER BY total DESC LIMIT 5';
  try {
    const rows = await new Promise((resolve, reject) => {
      db.all(query, params, (err, rows) => {
        if (err) reject(err);
        resolve(rows);
      });
    });
    res.json(rows);
  } catch (e) {
    console.error('Error fetching top categories:', e);
    res.status(500).json({ error: 'Failed to fetch top categories' });
  }
});

app.get('/stats/high-days', authenticateToken, async (req, res) => {
  const { fromDate, toDate } = req.query;
  let query = `
    SELECT date, SUM(amount) as total
    FROM expenses
    WHERE user_id = ? AND deleted = 0
  `;
  const params = [req.user.id];
  if (fromDate && toDate) {
    query += ' AND date BETWEEN ? AND ?';
    params.push(fromDate, toDate);
  }
  query += ' GROUP BY date ORDER BY total DESC LIMIT 5';
  try {
    const rows = await new Promise((resolve, reject) => {
      db.all(query, params, (err, rows) => {
        if (err) reject(err);
        resolve(rows);
      });
    });
    res.json(rows);
  } catch (e) {
    console.error('Fetch high days error:', e);
    res.status(500).json({ error: 'Failed to fetch high spending days' });
  }
});

app.get('/yearly', authenticateToken, async (req, res) => {
  const { fromDate, toDate } = req.query;
  let query = `
    SELECT strftime('%Y', date) as year, SUM(amount) as total
    FROM expenses
    WHERE user_id = ? AND deleted = 0
  `;
  const params = [req.user.id];
  if (fromDate && toDate) {
    query += ' AND date BETWEEN ? AND ?';
    params.push(fromDate, toDate);
  }
  query += ' GROUP BY year ORDER BY year';
  try {
    const rows = await new Promise((resolve, reject) => {
      db.all(query, params, (err, rows) => {
        if (err) reject(err);
        resolve(rows);
      });
    });
    res.json(rows);
  } catch (e) {
    console.error('Fetch yearly trends error:', e);
    res.status(500).json({ error: 'Failed to fetch yearly trends' });
  }
});

app.get('/', (req, res) => {
  res.sendFile('index.html', { root: 'public' });
});

app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});