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

const VALID_TICKET = 'strix_passed_2026';
// 🔑 СЕКРЕТНЫЙ ПАРОЛЬ АДМИНИСТРАТОРА
const ADMIN_SECRET = 'super_secret_admin_pass_2026';

// Middleware для проверки админ-пароля
function verifyAdmin(req, res, next) {
    const adminPass = req.headers['x-admin-secret'];
    if (adminPass && adminPass === ADMIN_SECRET) {
        next();
    } else {
        res.status(403).json({ success: false, message: 'Forbidden: Invalid Admin Secret' });
    }
}

// -------------------------------------------------------------
// 1. ВЫДАЧА УНИКАЛЬНОГО ТОКЕНА
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
// 2. ГЕНЕРАЦИЯ КЛЮЧА ОБЫЧНЫМ ПОЛЬЗОВАТЕЛЕМ
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
// 3. ПРОВЕРКА И АКТИВАЦИЯ КЛЮЧА В ИГРЕ
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

        // Первая активация: привязываем HWID и отсчитываем 7 дней (если это не бессрочный ключ)
        if (!row.hwid) {
            let newExpiresAt = row.expires_at;
            // Если срок меньше 50 лет — ставим 7 дней от момента первого входа
            if (new Date(row.expires_at).getFullYear() < 2070) {
                newExpiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();
            }

            db.run(`UPDATE keys SET hwid = ?, expires_at = ? WHERE key = ?`, [hwid, newExpiresAt, key], (updateErr) => {
                if (updateErr) {
                    return res.json({ success: false, message: 'HWID binding error' });
                }
                return res.json({ success: true, message: 'Key successfully activated!' });
            });
        } else if (row.hwid === hwid) {
            return res.json({ success: true, message: 'Access granted!' });
        } else {
            return res.json({ success: false, message: 'Key bound to another PC!' });
        }
    });
});

// =============================================================
// 👑 АДМИНСКИЕ ЭНДПОИНТЫ
// =============================================================

app.get('/api/admin/keys', verifyAdmin, (req, res) => {
    db.all(`SELECT * FROM keys ORDER BY expires_at DESC`, [], (err, rows) => {
        if (err) return res.json({ success: false, message: err.message });
        res.json({ success: true, keys: rows });
    });
});

// ИСПРАВЛЕНО: hwid ставится в NULL, чтобы ключ привязался к первому кто его введет
app.post('/api/admin/create-key', verifyAdmin, (req, res) => {
    const { days } = req.body;
    const newKey = generateRandomKey();
    
    let expiresAt;
    if (!days || parseInt(days) === -1) {
        expiresAt = new Date(Date.now() + 100 * 365 * 24 * 60 * 60 * 1000).toISOString();
    } else {
        expiresAt = new Date(Date.now() + parseInt(days) * 24 * 60 * 60 * 1000).toISOString();
    }

    db.run(`INSERT INTO keys (key, hwid, ip, expires_at) VALUES (?, NULL, 'ADMIN', ?)`, [newKey, expiresAt], (err) => {
        if (err) return res.json({ success: false, message: err.message });
        res.json({ success: true, key: newKey, expires_at: expiresAt });
    });
});

app.post('/api/admin/clear-db', verifyAdmin, (req, res) => {
    db.run(`DELETE FROM keys`, [], (err) => {
        if (err) return res.json({ success: false, message: err.message });
        db.run(`DELETE FROM tokens`, [], () => {
            res.json({ success: true, message: 'Database cleared successfully!' });
        });
    });
});

app.post('/api/admin/delete-key', verifyAdmin, (req, res) => {
    const { key } = req.body;
    db.run(`DELETE FROM keys WHERE key = ?`, [key], (err) => {
        if (err) return res.json({ success: false, message: err.message });
        res.json({ success: true, message: 'Key deleted successfully!' });
    });
});

// -------------------------------------------------------------
// АВТОМАТИЧЕСКАЯ ОЧИСТКА БАЗЫ ДАННЫХ
// -------------------------------------------------------------
setInterval(() => {
    const now = new Date().toISOString();
    db.run(`DELETE FROM keys WHERE expires_at < ?`, [now]);
    const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000).toISOString();
    db.run(`DELETE FROM tokens WHERE created_at < ?`, [oneHourAgo]);
}, 60 * 60 * 1000);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
