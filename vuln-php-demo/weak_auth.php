<?php
/**
 * VULNERABLE: Hardcoded credentials + broken auth logic
 * (CWE-798 hardcoded creds, CWE-287 improper authentication,
 *  plus a loose-comparison / type-juggling bug)
 *
 * Try:
 *   username=admin&password=letmein123   (hardcoded backdoor creds)
 *   password[]=x    (array bypass — some naive checks crash into truthy)
 *   Compare "0e123..." style hash tricks if you swap in md5() checks
 */

session_start();
$error = '';

// --- VULNERABLE: hardcoded backdoor creds baked into the app ---
const BACKDOOR_USER = 'admin';
const BACKDOOR_PASS = 'letmein123';
// FIX: never hardcode credentials; use environment-managed secrets, and
// remove debug/backdoor accounts before shipping.

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $user = $_POST['username'] ?? '';
    $pass = $_POST['password'] ?? '';

    // --- VULNERABLE LINE: loose comparison (==) invites type juggling ---
    if ($user == BACKDOOR_USER && $pass == BACKDOOR_PASS) {
        $_SESSION['auth'] = true;
        $_SESSION['user'] = $user;
    } else {
        $error = 'Invalid credentials';
    }
    // FIX: use strict comparison (===), and check against a hashed
    // password from a real user store with password_verify():
    //   if ($user === $realUser && password_verify($pass, $storedHash)) { ... }
}
?>
<!DOCTYPE html>
<html>
<head><title>Weak Auth Demo</title></head>
<body>
<h2>Login (weak/backdoored auth)</h2>
<?php if (!empty($_SESSION['auth'])): ?>
    <p>Logged in as <?= htmlspecialchars($_SESSION['user']) ?>. <a href="?logout=1">Logout</a></p>
<?php else: ?>
    <?php if ($error): ?><p style="color:red"><?= htmlspecialchars($error) ?></p><?php endif; ?>
    <form method="post">
        <input type="text" name="username" placeholder="username"><br>
        <input type="password" name="password" placeholder="password"><br>
        <button type="submit">Login</button>
    </form>
<?php endif; ?>
<?php if (isset($_GET['logout'])) { session_destroy(); echo '<script>location.href="weak_auth.php"</script>'; } ?>
</body>
</html>
