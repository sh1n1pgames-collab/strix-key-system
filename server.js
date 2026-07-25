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

// Создаем расширенную таблицу с полем ip и токенами
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

// -------------------------------------------------------------
// 1. ВЫДАЧА УНИКАЛЬНОГО ТОКЕНА ДЛЯ СТРАНИЦЫ
// -------------------------------------------------------------
app.get('/api/get-token', (req, res) => {
    const clientIp = req.ip;
    const token = crypto.randomBytes(16).toString('hex');
    const now = new Date().toISOString();

    // Сохраняем временный токен для этого IP
    db.run(`INSERT INTO tokens (token, ip, created_at) VALUES (?, ?, ?)`, [token, clientIp, now], (err) => {
        if (err) {
            return res.json({ success: false, error: 'Token generation error' });
        }
        res.json({ success: true, token: token });
    });
});

// -------------------------------------------------------------
// 2. ГЕНЕРАЦИЯ КЛЮЧА С ЗАЩИТОЙ ПО IP (1 раз в 7 дней)
// -------------------------------------------------------------
app.post('/api/generate-key', (req, res) => {
    const clientIp = req.ip;
    const { token } = req.body;

    if (!token) {
        return.json({ success: false, message: 'Invalid session token' });
    }

    // Проверяем, существует ли токен и принадлежит ли он этому IP
    db.get(`SELECT * FROM tokens WHERE token = ? AND ip = ?`, [token, clientIp], (err, tokenRow) => {
        if (err || !tokenRow) {
            return.json({ success: false, message: 'Security check failed. Please refresh the page.' });
        }

        // Проверяем, получал ли этот IP ключ за последние 7 дней
        db.get(`SELECT * FROM keys WHERE ip = ? ORDER BY expires_at DESC LIMIT 1`, [clientIp], (err, row) => {
            if (row) {
                const now = new Date();
                const expirationDate = new Date(row.expires_at);

                if (now < expirationDate) {
                    return.json({ 
                        success: false, 
                        message: 'You have already generated a key from this IP. Try again later.' 
                    });
                }
            }

            // Удаляем использованный токен, чтобы его нельзя было применить повторно
            db.run(`DELETE FROM tokens WHERE token = ?`, [token]);

            // Создаем новый ключ
            const newKey = generateRandomKey();
            const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();

            db.run(`INSERT INTO keys (key, hwid, ip, expires_at) VALUES (?, NULL, ?, ?)`, [newKey, clientIp, expiresAt], (insertErr) => {
                if (insertErr) {
                    return.status(500).json({ success: false, error: 'Database save error' });
                }
                res.json({
                    success: true,
                    key: newKey,
                    expires_at: expiresAt
                });
            });
        });
    });
});

// -------------------------------------------------------------
// 3. ПРОВЕРКА КЛЮЧА И HWID В ИГРЕ
// -------------------------------------------------------------
app.post('/api/verify-key', (req, res) => {
    const { key, hwid } = req.body;

    if (!key || !hwid) {
        return.json({ success: false, message: 'Missing key or HWID' });
    }

    db.get(`SELECT * FROM keys WHERE key = ?`, [key], (err, row) => {
        if (err || !row) {
            return.json({ success: false, message: 'Key not found in system!' });
        }

        const now = new Date();
        const expirationDate = new Date(row.expires_at);

        if (now > expirationDate) {
            return.json({ success: false, message: 'Key has expired (7 days limit)!' });
        }

        if (!row.hwid) {
            db.run(`UPDATE keys SET hwid = ? WHERE key = ?`, [hwid, key], (updateErr) => {
                if (updateErr) {
                    return.json({ success: false, message: 'HWID binding error' });
                }
                return.json({ success: true, message: 'Key successfully activated and bound to your PC!' });
            });
        } else if (row.hwid === hwid) {
            return.json({ success: true, message: 'Access granted!' });
        } else {
            return.json({ success: false, message: 'This key is bound to another device!' });
        }
    });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
