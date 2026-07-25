const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors());

// Подключаем или создаем базовую БД (SQLite)
const db = new sqlite3.Database('./keys.db');

db.serialize(() => {
    db.run(`
        CREATE TABLE IF NOT EXISTS keys (
            key TEXT PRIMARY KEY,
            hwid TEXT,
            expires_at DATETIME
        )
    `);
});

// Генератор случайного ключа
function generateRandomKey() {
    return 'STRIX-' + Math.random().toString(36).substring(2, 8).toUpperCase() + '-' + Math.random().toString(36).substring(2, 8).toUpperCase();
}

// -------------------------------------------------------------
// 1. ЭНДПОИНТ ДЛЯ САЙТА: Создание ключа после просмотра рекламы
// -------------------------------------------------------------
app.post('/api/generate-key', (req, res) => {
    const newKey = generateRandomKey();
    
    // Рассчитываем дату истечения (+7 дней от текущего момента)
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();

    db.run(`INSERT INTO keys (key, hwid, expires_at) VALUES (?, NULL, ?)`, [newKey, expiresAt], (err) => {
        if (err) {
            return res.status(500).json({ success: false, error: 'Ошибка сохранения ключа' });
        }
        res.json({
            success: true,
            key: newKey,
            expires_at: expiresAt
        });
    });
});

// -------------------------------------------------------------
// 2. ЭНДПОИНТ ДЛЯ СКРИПТА: Проверка ключа и HWID
// -------------------------------------------------------------
app.post('/api/verify-key', (req, res) => {
    const { key, hwid } = req.body;

    if (!key || !hwid) {
        return res.json({ success: false, message: 'Отсутствует ключ или HWID' });
    }

    // Ищем ключ в базе данных
    db.get(`SELECT * FROM keys WHERE key = ?`, [key], (err, row) => {
        if (err || !row) {
            return res.json({ success: false, message: 'Ключ не найден в системе!' });
        }

        // 1. Проверяем срок действия (не истёк ли)
        const now = new Date();
        const expirationDate = new Date(row.expires_at);

        if (now > expirationDate) {
            return res.json({ success: false, message: 'Срок действия ключа (7 дней) истёк!' });
        }

        // 2. Проверяем HWID
        if (!row.hwid) {
            // Первая активация: привязываем текущий HWID к этому ключу
            db.run(`UPDATE keys SET hwid = ? WHERE key = ?`, [hwid, key], (updateErr) => {
                if (updateErr) {
                    return res.json({ success: false, message: 'Ошибка привязкa HWID' });
                }
                return res.json({ success: true, message: 'Ключ успешно активирован и привязан к вашему ПК!' });
            });
        } else if (row.hwid === hwid) {
            // HWID совпадает с сохраненным
            return res.json({ success: true, message: 'Доступ разрешен!' });
        } else {
            // HWID не совпадает (попытка передать ключ другу)
            return res.json({ success: false, message: 'Этот ключ привязан к другому ПК!' });
        }
    });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Сервер запущен на порту ${PORT}`));
