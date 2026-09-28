<?php
/**
 * VULNERABLE: Local File Inclusion / Path Traversal (CWE-98 / CWE-22)
 *
 * `page` is passed straight into include() with no validation, and
 * no allowlist restricting it to a known set of files.
 *
 * Try:
 *   /lfi.php?page=about
 *   /lfi.php?page=../../../../etc/passwd%00        (null-byte trick, PHP<5.3.4 only, kept for reference)
 *   /lfi.php?page=php://filter/convert.base64-encode/resource=lfi.php   (source disclosure)
 *   /lfi.php?page=../config/seed_db.php
 */

$page = $_GET['page'] ?? 'about';

echo "<h2>Simple page loader (vulnerable to LFI)</h2>";
echo "<p>Requested page: " . htmlspecialchars($page) . "</p><hr>";

// --- VULNERABLE LINE ---
include __DIR__ . '/pages/' . $page . '.php';
// FIX: allowlist approach —
// $allowed = ['about' => 'about.php', 'contact' => 'contact.php'];
// if (!isset($allowed[$page])) { http_response_code(404); exit('Not found'); }
// include __DIR__ . '/pages/' . $allowed[$page];
