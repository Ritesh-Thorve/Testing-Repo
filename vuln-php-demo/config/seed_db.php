<?php
// Run once via CLI: php config/seed_db.php
// Creates data.sqlite with a users table + sample rows for sqli.php / idor.php

$dbPath = __DIR__ . '/../data.sqlite';
$pdo = new PDO('sqlite:' . $dbPath);
$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

$pdo->exec("DROP TABLE IF EXISTS users");
$pdo->exec("CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    password TEXT NOT NULL,
    email TEXT NOT NULL,
    is_admin INTEGER DEFAULT 0
)");

$stmt = $pdo->prepare("INSERT INTO users (username, password, email, is_admin) VALUES (?, ?, ?, ?)");
$stmt->execute(['alice', 'alicepw123', 'alice@example.com', 0]);
$stmt->execute(['bob',   'bobpw456',   'bob@example.com',   0]);
$stmt->execute(['admin', 'S3cretAdminPass!', 'admin@example.com', 1]);

echo "Seeded {$dbPath} with 3 users (alice, bob, admin).\n";
