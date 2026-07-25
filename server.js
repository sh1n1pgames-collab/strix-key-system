const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
const path = require('path');

const app = express();
app.use(express.json());
app.use(cors());

// Раздаем красивый сайт из папки 'public' по главному адресу
app.use(express.static(path.join(__dirname, 'public')));

// Подключаем базу данных SQLite
const db = new sqlite3.Database('./keys.db', (err) => {
    if (err) {
        console.error('Database connection error:', err.message);
    } else {
        console.log('Connected to SQLite database successfully.');
    }
});

// Создаем таблицу для ключей
db.serialize(() => {
    db.run(`
        CREATE TABLE IF NOT EXISTS keys (
            key TEXT PRIMARY KEY,
            hwid TEXT,
            expires_at DATETIME
        )
    `);
});

// Генератор ключа
function generateRandomKey() {
    return 'STRIX-' + Math.random().toString(36).substring(2, 8).toUpperCase() + '-' + Math.random().toString(36).substring(2, 8).toUpperCase();
}

// -------------------------------------------------------------
// ЭНДПОИНТ: Генерация ключа (вызывается кнопкой на сайте)
// -------------------------------------------------------------
app.post('/api/generate-key', (req, res) => {
    const newKey = generateRandomKey();
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();

    db.run(`INSERT INTO keys (key, hwid, expires_at) VALUES (?, NULL, ?)`, [newKey, expiresAt], (err) => {
        if (err) {
            return res.status(500).json({ success: false, error: 'Database save error' });
        }
        res.json({
            success: true,
            key: newKey,
            expires_at: expiresAt
        });
    });
});

// -------------------------------------------------------------
// ЭНДПОИНТ: Проверка ключа и HWID (вызывается из скрипта в игре)
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
            return res.json({ success: false, message: 'Key has expired (7 days limit)!' });
        }

        if (!row.hwid) {
            db.run(`UPDATE keys SET hwid = ? WHERE key = ?`, [hwid, key], (updateErr) => {
                if (updateErr) {
                    return res.json({ success: false, message: 'HWID binding error' });
                }
                return res.json({ success: true, message: 'Key successfully activated and bound to your PC!' });
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
