const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');

const app = express();
app.use(express.json());
app.use(cors());

app.set('trust proxy', true);

app.use(express.static(path.join(__dirname, 'public')));

const db = new sqlite3.Database('./keys.db', (err) => {
    if (err) {
        console.error('Database error:', err.message);
    } else {
        console.log('Database connected.');
    }
});

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

// Секретный билет, который передается в ссылке после выполнения задания
const VALID_TICKET = 'strix_passed_2026';

// -------------------------------------------------------------
// 1. ВЫДАЧА ТОКЕНА (Только при наличии верного билета)
// -------------------------------------------------------------
app.post('/api/get-token', (req, res) => {
    const clientIp = req.ip;
    const { ticket } = req.body;

    // Если билет отсутствует или неверный — отказываем в выдаче токена
    if (!ticket || ticket !== VALID_TICKET) {
        return res.json({ success: false, message: 'Access Denied. Task not verified.' });
    }

    const token = crypto.randomBytes(16).toString('hex');
    const now = new Date().toISOString();

    db.run(`INSERT INTO tokens (token, ip, created_at) VALUES (?, ?, ?)`, [token, clientIp, now], (err) => {
        if (err) {
            return res.json({ success: false, message: 'Token error' });
        }
        res.json({ success: true, token: token });
    });
});

// -------------------------------------------------------------
// 2. ГЕНЕРАЦИЯ КЛЮЧА
// -------------------------------------------------------------
app.post('/api/generate-key', (req, res) => {
    const clientIp = req.ip;
    const { token } = req.body;

    if (!token) {
        return res.json({ success: false, message: 'Invalid token' });
    }

    db.get(`SELECT * FROM tokens WHERE token = ? AND ip = ?`, [token, clientIp], (err, tokenRow) => {
        if (err || !tokenRow) {
            return res.json({ success: false, message: 'Security check failed. Please return to the task link.' });
        }

        db.get(`SELECT * FROM keys WHERE ip = ? ORDER BY expires_at DESC LIMIT 1`, [clientIp], (err, row) => {
            if (row) {
                const now = new Date();
                const expirationDate = new Date(row.expires_at);

                if (now < expirationDate) {
                    return res.json({ 
                        success: false, 
                        message: 'You have already generated a key from this IP. Try again in 7 days.' 
                    });
                }
            }

            db.run(`DELETE FROM tokens WHERE token = ?`, [token]);

            const newKey = generateRandomKey();
            const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();

            db.run(`INSERT INTO keys (key, hwid, ip, expires_at) VALUES (?, NULL, ?, ?)`, [newKey, clientIp, expiresAt], (insertErr) => {
                if (insertErr) {
                    return res.status(500).json({ success: false, message: 'Database error' });
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
// 3. ПРОВЕРКА КЛЮЧА В ИГРЕ
// -------------------------------------------------------------
app.post('/api/verify-key', (req, res) => {
    const { key, hwid } = req.body;

    if (!key || !hwid) {
        return res.json({ success: false, message: 'Missing key or HWID' });
    }

    db.get(`SELECT * FROM keys WHERE key = ?`, [key], (err, row) => {
        if (err || !row) {
            return res.json({ success: false, message: 'Key not found!' });
        }

        const now = new Date();
        const expirationDate = new Date(row.expires_at);

        if (now > expirationDate) {
            return res.json({ success: false, message: 'Key expired!' });
        }

        if (!row.hwid) {
            db.run(`UPDATE keys SET hwid = ? WHERE key = ?`, [hwid, key], (updateErr) => {
                if (updateErr) {
                    return res.json({ success: false, message: 'HWID bind error' });
                }
                return res.json({ success: true, message: 'Key bound to device!' });
            });
        } else if (row.hwid === hwid) {
            return res.json({ success: true, message: 'Access granted!' });
        } else {
            return res.json({ success: false, message: 'Key bound to another device!' });
        }
    });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
