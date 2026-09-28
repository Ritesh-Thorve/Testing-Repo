<?php
/**
 * VULNERABLE: Insecure Direct Object Reference (CWE-639)
 *
 * Any authenticated-ish user (here, simulated via a `user_id`
 * session cookie set by "logging in" as alice/bob) can fetch ANY
 * other user's profile by simply changing `id` in the URL — there
 * is no check that the requested record belongs to the caller.
 *
 * Try:
 *   /idor.php?login=alice   (sets session as user id 1)
 *   /idor.php?id=1          (your own profile — fine)
 *   /idor.php?id=3          (admin's profile — should NOT be visible to alice)
 */

session_start();

$dbPath = __DIR__ . '/data.sqlite';
$pdo = new PDO('sqlite:' . $dbPath);
$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

// Fake "login" for demo purposes
if (isset($_GET['login'])) {
    $stmt = $pdo->prepare("SELECT id FROM users WHERE username = ?");
    $stmt->execute([$_GET['login']]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    if ($row) $_SESSION['user_id'] = $row['id'];
}

$loggedInId = $_SESSION['user_id'] ?? null;
$requestedId = $_GET['id'] ?? $loggedInId;

$profile = null;
if ($requestedId) {
    // --- VULNERABLE: no ownership check, no admin-only gate ---
    $stmt = $pdo->prepare("SELECT id, username, email, is_admin FROM users WHERE id = ?");
    $stmt->execute([$requestedId]);
    $profile = $stmt->fetch(PDO::FETCH_ASSOC);
    // FIX:
    // if ($requestedId != $loggedInId && !currentUserIsAdmin()) {
    //     http_response_code(403); exit('Forbidden');
    // }
}
?>
<!DOCTYPE html>
<html>
<head><title>IDOR Demo</title></head>
<body>
<h2>Profile viewer (vulnerable to IDOR)</h2>
<p>Logged in as user id: <?= htmlspecialchars($loggedInId ?? 'none') ?>
   (<a href="?login=alice">login as alice</a> | <a href="?login=bob">login as bob</a>)</p>
<form method="get">
    <input type="text" name="id" placeholder="user id" value="<?= htmlspecialchars($requestedId ?? '') ?>">
    <button type="submit">View profile</button>
</form>
<?php if ($profile): ?>
    <pre><?= htmlspecialchars(print_r($profile, true)) ?></pre>
<?php endif; ?>
</body>
</html>
