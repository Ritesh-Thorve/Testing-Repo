<?php
/**
 * Landing page — links to each intentionally vulnerable demo.
 * LOCAL / ISOLATED TESTING ONLY. See README.md.
 */
$demos = [
    'sqli.php'          => 'SQL Injection',
    'xss.php'           => 'Reflected + Stored XSS',
    'lfi.php'           => 'Local File Inclusion',
    'cmdi.php'          => 'OS Command Injection',
    'upload.php'        => 'Unrestricted File Upload',
    'idor.php'          => 'Insecure Direct Object Reference',
    'deserialize.php'   => 'Insecure Deserialization',
    'ssrf.php'          => 'Server-Side Request Forgery',
    'weak_auth.php'     => 'Hardcoded Creds / Broken Auth',
    'xxe.php'           => 'XML External Entity Injection',
];
?>
<!DOCTYPE html>
<html>
<head><title>Vulnerable PHP Demo</title></head>
<body>
<h1>Intentionally Vulnerable PHP Demo</h1>
<p style="color:red"><strong>Local / isolated testing only.</strong> Do not expose to the internet.</p>
<p>Run <code>php config/seed_db.php</code> once first (needed by sqli.php and idor.php).</p>
<ul>
<?php foreach ($demos as $file => $label): ?>
    <li><a href="<?= $file ?>"><?= htmlspecialchars($label) ?></a> — <code><?= $file ?></code></li>
<?php endforeach; ?>
</ul>
</body>
</html>
