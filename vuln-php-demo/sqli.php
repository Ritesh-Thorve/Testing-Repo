<?php
/**
 * VULNERABLE: SQL Injection (CWE-89)
 *
 * The `username` parameter is concatenated directly into the SQL
 * string with no parameterization or escaping.
 *
 * Try:
 *   /sqli.php?username=alice
 *   /sqli.php?username=' OR '1'='1
 *   /sqli.php?username=nonexistent' UNION SELECT 1,username,password,email,is_admin FROM users--
 *
 * Run config/seed_db.php first to create the sqlite DB.
 */

$dbPath = __DIR__ . '/data.sqlite';
$pdo = new PDO('sqlite:' . $dbPath);
$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

$username = $_GET['username'] ?? '';
$results = [];
$error = null;

if ($username !== '') {
    // --- VULNERABLE LINE ---
    $query = "SELECT id, username, email FROM users WHERE username = '" . $username . "'";
    // FIX: $stmt = $pdo->prepare("SELECT id, username, email FROM users WHERE username = ?");
    // FIX: $stmt->execute([$username]);

    try {
        $stmt = $pdo->query($query);
        $results = $stmt->fetchAll(PDO::FETCH_ASSOC);
    } catch (PDOException $e) {
        $error = $e->getMessage();
    }
}
?>
<!DOCTYPE html>
<html>
<head><title>SQLi Demo</title></head>
<body>
<h2>User lookup (vulnerable to SQLi)</h2>
<form method="get">
    <input type="text" name="username" placeholder="username" value="<?= htmlspecialchars($username) ?>">
    <button type="submit">Search</button>
</form>

<p><strong>Query executed:</strong> <code><?= htmlspecialchars($query ?? '') ?></code></p>

<?php if ($error): ?>
    <p style="color:red">SQL Error: <?= htmlspecialchars($error) ?></p>
<?php endif; ?>

<table border="1" cellpadding="5">
    <tr><th>id</th><th>username</th><th>email</th></tr>
    <?php foreach ($results as $row): ?>
        <tr>
            <td><?= htmlspecialchars($row['id']) ?></td>
            <td><?= htmlspecialchars($row['username']) ?></td>
            <td><?= htmlspecialchars($row['email']) ?></td>
        </tr>
    <?php endforeach; ?>
</table>
</body>
</html>
