const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');

const app = express();
app.use(express.json());
app.use(cors());

// Убеждаемся, что Render правильно определяет IP-адреса за прокси
app.set('trust proxy', true);

app.use(express.static(path.join(__dirname, 'public')));

const db = new sqlite3.Database('./keys.db', (err) => {
    if (err) {
        console.error('Database connection error:', err.message);
    } else {
        console.log('Connected to SQLite database successfully.');
    }
});

// Создаем таблицы для ключей и защитных токенов
db.serialize(() => {
    db.run(`
        CREATE TABLE IF NOT EXISTS keys (
            key TEXT PRIMARY KEY,
            hwid TEXT,
            ip TEXT,
            expires_at DATETIME
        )
    `);

    db.run(`
        CREATE TABLE IF NOT EXISTS tokens (
            token TEXT PRIMARY KEY,
            ip TEXT,
            created_at DATETIME
        )
    `);
});

function generateRandomKey() {
    return 'STRIX-' + Math.random().toString(36).substring(2, 8).toUpperCase() + '-' + Math.random().toString(36).substring(2, 8).toUpperCase();
}

// Секретный билет, передаваемый при выполнении задания
const VALID_TICKET = 'strix_passed_2026';

// -------------------------------------------------------------
// 1. ВЫДАЧА УНИКАЛЬНОГО ТОКЕНА (Только при наличии билета)
// -------------------------------------------------------------
app.post('/api/get-token', (req, res) => {
    const clientIp = req.ip;
    const { ticket } = req.body;

    if (!ticket || ticket !== VALID_TICKET) {
        return res.json({ success: false, message: 'Access Denied. Task not verified.' });
    }

    const token = crypto.randomBytes(16).toString('hex');
    const now = new Date().toISOString();

    db.run(`INSERT INTO tokens (token, ip, created_at) VALUES (?, ?, ?)`, [token, clientIp, now], (err) => {
        if (err) {
            return res.json({ success: false, message: 'Token generation error' });
        }
        res.json({ success: true, token: token });
    });
});

// -------------------------------------------------------------
// 2. ГЕНЕРАЦИЯ КЛЮЧА (Срок на активацию — 1 час)
// -------------------------------------------------------------
app.post('/api/generate-key', (req, res) => {
    const clientIp = req.ip;
    const { token } = req.body;

    if (!token) {
        return res.json({ success: false, message: 'Invalid session token' });
    }

    db.get(`SELECT * FROM tokens WHERE token = ? AND ip = ?`, [token, clientIp], (err, tokenRow) => {
        if (err || !tokenRow) {
            return res.json({ success: false, message: 'Security check failed. Please refresh via the task link.' });
        }

        db.get(`SELECT * FROM keys WHERE ip = ? ORDER BY expires_at DESC LIMIT 1`, [clientIp], (err, row) => {
            if (row) {
                const now = new Date();
                const expirationDate = new Date(row.expires_at);

                if (now < expirationDate) {
                    return res.json({ 
                        success: false, 
                        message: 'You have already generated a key from this IP. Try again later.' 
                    });
                }
            }

            db.run(`DELETE FROM tokens WHERE token = ?`, [token]);

            const newKey = generateRandomKey();
            // Даем 1 час на первую активацию в игре
            const activationDeadline = new Date(Date.now() + 1 * 60 * 60 * 1000).toISOString();

            db.run(`INSERT INTO keys (key, hwid, ip, expires_at) VALUES (?, NULL, ?, ?)`, [newKey, clientIp, activationDeadline], (insertErr) => {
                if (insertErr) {
                    return res.status(500).json({ success: false, message: 'Database save error' });
                }
                res.json({
                    success: true,
                    key: newKey,
                    expires_at: activationDeadline
                });
            });
        });
    });
});

// -------------------------------------------------------------
// 3. ПРОВЕРКА И АКТИВАЦИЯ КЛЮЧА В ИГРЕ (7 дней от активации)
// -------------------------------------------------------------
app.post('/api/verify-key', (req, res) => {
    const { key, hwid } = req.body;

    if (!key || !hwid) {
        return res.json({ success: false, message: 'Missing key or HWID' });
    }

    db.get(`SELECT * FROM keys WHERE key = ?`, [key], (err, row) => {
        if (err || !row) {
            return res.json({ success: false, message: 'Key not found in system!' });
        }

        const now = new Date();
        const expirationDate = new Date(row.expires_at);

        if (now > expirationDate) {
            return res.json({ success: false, message: 'Key has expired!' });
        }

        // Первая активация: привязываем HWID и отсчитываем 7 дней с этого момента
        if (!row.hwid) {
            const sevenDaysFromNow = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();

            db.run(`UPDATE keys SET hwid = ?, expires_at = ? WHERE key = ?`, [hwid, sevenDaysFromNow, key], (updateErr) => {
                if (updateErr) {
                    return res.json({ success: false, message: 'HWID binding error' });
                }
                return res.json({ success: true, message: 'Key successfully activated and bound to your PC! 7 days granted.' });
            });
        } else if (row.hwid === hwid) {
            return res.json({ success: true, message: 'Access granted!' });
        } else {
            return res.json({ success: false, message: 'This key is bound to another device!' });
        }
    });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
