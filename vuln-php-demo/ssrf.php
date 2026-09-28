<?php
/**
 * VULNERABLE: Server-Side Request Forgery (CWE-918)
 *
 * `url` is fetched server-side with no allowlist, no scheme
 * restriction, and no block on internal/link-local addresses —
 * classic path to hitting cloud metadata endpoints or internal
 * services that aren't meant to be reachable from outside.
 *
 * Try:
 *   /ssrf.php?url=https://example.com
 *   /ssrf.php?url=http://127.0.0.1:8000/lfi.php?page=../config/seed_db.php
 *   /ssrf.php?url=file:///etc/passwd
 *   /ssrf.php?url=http://169.254.169.254/latest/meta-data/   (cloud metadata, if applicable)
 */

$url = $_GET['url'] ?? '';
$body = '';
$error = '';

if ($url !== '') {
    // --- VULNERABLE LINE ---
    $ctx = stream_context_create(['http' => ['timeout' => 3]]);
    $body = @file_get_contents($url, false, $ctx);
    if ($body === false) $error = 'Request failed';
    // FIX:
    // - allowlist destination hosts/schemes
    // - resolve DNS first and reject private/link-local/loopback ranges (SSRF via DNS rebinding too)
    // - disable following redirects, or re-validate the redirect target
    // - use a dedicated egress proxy with network-level restrictions as defense in depth
}
?>
<!DOCTYPE html>
<html>
<head><title>SSRF Demo</title></head>
<body>
<h2>URL fetcher (vulnerable to SSRF)</h2>
<form method="get">
    <input type="text" name="url" placeholder="https://example.com" size="50" value="<?= htmlspecialchars($url) ?>">
    <button type="submit">Fetch</button>
</form>
<?php if ($error): ?><p style="color:red"><?= htmlspecialchars($error) ?></p><?php endif; ?>
<pre><?= htmlspecialchars(substr($body ?? '', 0, 2000)) ?></pre>
</body>
</html>
