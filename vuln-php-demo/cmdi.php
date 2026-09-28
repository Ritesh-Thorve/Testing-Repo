<?php
/**
 * VULNERABLE: OS Command Injection (CWE-78)
 *
 * `host` is passed straight into shell_exec() via string
 * concatenation with no escaping and no input validation.
 *
 * Try:
 *   /cmdi.php?host=127.0.0.1
 *   /cmdi.php?host=127.0.0.1;whoami
 *   /cmdi.php?host=127.0.0.1 && cat /etc/passwd
 *   /cmdi.php?host=$(id)
 */

$host = $_GET['host'] ?? '';
$output = '';

if ($host !== '') {
    // --- VULNERABLE LINE ---
    $cmd = "ping -c 1 " . $host;
    $output = shell_exec($cmd . ' 2>&1');
    // FIX: validate strictly (e.g. filter_var($host, FILTER_VALIDATE_IP))
    // FIX: if shelling out is unavoidable, use escapeshellarg():
    //   $cmd = "ping -c 1 " . escapeshellarg($host);
    // FIX (best): avoid shell_exec entirely; use a PHP sockets/DNS check instead.
}
?>
<!DOCTYPE html>
<html>
<head><title>Command Injection Demo</title></head>
<body>
<h2>Ping a host (vulnerable to command injection)</h2>
<form method="get">
    <input type="text" name="host" placeholder="host" value="<?= htmlspecialchars($host) ?>">
    <button type="submit">Ping</button>
</form>
<?php if ($host !== ''): ?>
    <p><strong>Command:</strong> <code><?= htmlspecialchars($cmd) ?></code></p>
    <pre><?= htmlspecialchars($output) ?></pre>
<?php endif; ?>
</body>
</html>
