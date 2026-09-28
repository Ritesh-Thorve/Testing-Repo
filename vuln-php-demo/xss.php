<?php
/**
 * VULNERABLE: Reflected + Stored XSS (CWE-79)
 *
 * `comment` is stored in a flat file and echoed back with no output
 * encoding, and `name` is reflected directly with no encoding either.
 *
 * Try:
 *   /xss.php?name=<script>alert(document.domain)</script>
 *   Post a comment: <img src=x onerror=alert('stored-xss')>
 */

$storeFile = __DIR__ . '/xss_comments.txt';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['comment'])) {
    // --- VULNERABLE: stored, unsanitized ---
    file_put_contents($storeFile, $_POST['comment'] . "\n", FILE_APPEND);
    // FIX: sanitize on the way in AND encode on the way out; never trust one layer alone
}

$name = $_GET['name'] ?? 'guest';
$comments = file_exists($storeFile) ? file($storeFile) : [];
?>
<!DOCTYPE html>
<html>
<head><title>XSS Demo</title></head>
<body>
<!-- VULNERABLE LINE: reflected, unescaped -->
<h2>Welcome, <?= $name ?></h2>
<!-- FIX: <h2>Welcome, <?= htmlspecialchars($name, ENT_QUOTES, 'UTF-8') ?></h2> -->

<form method="post">
    <input type="text" name="comment" placeholder="Leave a comment">
    <button type="submit">Post</button>
</form>

<h3>Comments:</h3>
<ul>
<?php foreach ($comments as $c): ?>
    <!-- VULNERABLE LINE: stored, unescaped -->
    <li><?= $c ?></li>
    <!-- FIX: <li><?= htmlspecialchars($c, ENT_QUOTES, 'UTF-8') ?></li> -->
<?php endforeach; ?>
</ul>
</body>
</html>
