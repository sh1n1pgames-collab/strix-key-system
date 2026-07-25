const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
const path = require('path');

const app = express();
app.use(express.json());
app.use(cors());

// Раздаем статические файлы сайта из папки 'public' по главному адресу
app.use(express.static(path.join(__dirname, 'public')));

// Подключаем или создаем локальную базу данных SQLite
const db = new sqlite3.Database('./keys.db', (err) => {
    if (err) {
        console.error('Ошибка подключения к базе данных:', err.message);
    } else {
        console.log('Успешное подключение к базе данных SQLite.');
    }
});

// Создаем таблицу для ключей, если её еще нет
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
// 1. ЭНДПОИНТ ДЛЯ САЙТА: Создание ключа
// -------------------------------------------------------------
app.post('/api/generate-key', (req, res) => {
    const newKey = generateRandomKey();
    
    // Ключ действует ровно 7 дней с момента создания
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();

    db.run(`INSERT INTO keys (key, hwid, expires_at) VALUES (?, NULL, ?)`, [newKey, expiresAt], (err) => {
        if (err) {
            return res.status(500).json({ success: false, error: 'Ошибка сохранения ключа в базе данных' });
        }
        res.json({
            success: true,
            key: newKey,
            expires_at: expiresAt
        });
    });
});

// -------------------------------------------------------------
// 2. ЭНДПОИНТ ДЛЯ СКРИПТА В ИГРЕ: Проверка ключа и HWID
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

        // Проверяем срок действия ключа (не истекли ли 7 дней)
        const now = new Date();
        const expirationDate = new Date(row.expires_at);

        if (now > expirationDate) {
            return res.json({ success: false, message: 'Срок действия ключа (7 дней) истёк!' });
        }

        // Проверяем привязку по HWID
        if (!row.hwid) {
            // Первая активация: привязываем железо к этому ключу
            db.run(`UPDATE keys SET hwid = ? WHERE key = ?`, [hwid, key], (updateErr) => {
                if (updateErr) {
                    return res.json({ success: false, message: 'Ошибка привязки HWID' });
                }
                return res.json({ success: true, message: 'Ключ успешно активирован и привязан к ПК!' });
            });
        } else if (row.hwid === hwid) {
            // HWID совпадает — доступ разрешен
            return res.json({ success: true, message: 'Доступ разрешен!' });
        } else {
            // HWID не совпадает (попытка использовать чужой ключ)
            return res.json({ success: false, message: 'Этот ключ привязан к другому устройству!' });
        }
    });
});

// Запуск сервера на порту, который выдает Render, либо на 3000 локально
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Сервер успешно запущен и работает на порту ${PORT}`);
});
