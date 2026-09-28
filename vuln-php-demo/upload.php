<?php
/**
 * VULNERABLE: Unrestricted File Upload (CWE-434)
 *
 * No check on file extension, MIME type, or content — anything
 * (including a .php webshell) is saved into a web-accessible
 * directory and can then be requested and executed directly.
 *
 * Try:
 *   Upload a file named shell.php containing: <?php system($_GET['c']); ?>
 *   Then browse to /uploads/shell.php?c=id
 */

$uploadDir = __DIR__ . '/uploads/';
if (!is_dir($uploadDir)) mkdir($uploadDir, 0777, true);

$message = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['file'])) {
    $name = $_FILES['file']['name'];
    $tmp  = $_FILES['file']['tmp_name'];

    // --- VULNERABLE: no extension/MIME allowlist, no re-encoding, no random filename ---
    $dest = $uploadDir . basename($name);
    move_uploaded_file($tmp, $dest);
    $message = "Uploaded to uploads/" . htmlspecialchars(basename($name));

    // FIX:
    // $allowedExt = ['jpg','jpeg','png','gif'];
    // $ext = strtolower(pathinfo($name, PATHINFO_EXTENSION));
    // if (!in_array($ext, $allowedExt)) { die('Rejected'); }
    // $finfo = finfo_open(FILEINFO_MIME_TYPE);
    // $mime = finfo_file($finfo, $tmp);
    // if (!in_array($mime, ['image/jpeg','image/png','image/gif'])) { die('Rejected'); }
    // $safeName = bin2hex(random_bytes(16)) . '.' . $ext;
    // move_uploaded_file($tmp, $uploadDir . $safeName);
    // FIX: also serve uploads/ from a directory with PHP execution disabled.
}
?>
<!DOCTYPE html>
<html>
<head><title>Upload Demo</title></head>
<body>
<h2>File upload (no restrictions)</h2>
<form method="post" enctype="multipart/form-data">
    <input type="file" name="file">
    <button type="submit">Upload</button>
</form>
<p><?= $message ?></p>
</body>
</html>
