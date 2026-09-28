<?php
/**
 * VULNERABLE: XML External Entity Injection (CWE-611)
 *
 * External entity loading is not disabled before parsing
 * user-supplied XML, allowing local file disclosure or SSRF via
 * DOCTYPE/ENTITY declarations.
 *
 * Try posting this as raw XML body (Content-Type: application/xml):
 *
 *   <?xml version="1.0"?>
 *   <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
 *   <root><data>&xxe;</data></root>
 *
 * curl example:
 *   curl -X POST --data-binary @payload.xml http://127.0.0.1:8000/xxe.php
 */

$raw = file_get_contents('php://input');
$result = '';
$error = '';

if ($raw !== '') {
    // --- VULNERABLE: external entity loading left enabled ---
    // (libxml_disable_entity_loader is a no-op / removed in PHP 8+,
    //  where LIBXML_NOENT + external DOCTYPE together are what enable this)
    $doc = new DOMDocument();
    $ok = @$doc->loadXML($raw, LIBXML_NOENT);
    // FIX:
    // $doc->loadXML($raw, LIBXML_NOENT | LIBXML_DTDLOAD ^ LIBXML_DTDLOAD); // i.e. don't pass DTDLOAD at all
    // Simpler fix: strip/reject any input containing "<!DOCTYPE" before parsing,
    // and never pass LIBXML_NOENT with external DTD loading permitted.

    if ($ok) {
        $result = $doc->textContent;
    } else {
        $error = 'Failed to parse XML';
    }
}
?>
<!DOCTYPE html>
<html>
<head><title>XXE Demo</title></head>
<body>
<h2>XML parser endpoint (vulnerable to XXE)</h2>
<p>POST raw XML to this endpoint (see comments in xxe.php for a payload).</p>
<form method="post" onsubmit="return false;">
    <textarea id="xml" rows="8" cols="60" placeholder="Paste XML and click Submit (uses fetch)"></textarea><br>
    <button onclick="submitXml()">Submit</button>
</form>
<pre><?= htmlspecialchars($result) ?></pre>
<?php if ($error): ?><p style="color:red"><?= htmlspecialchars($error) ?></p><?php endif; ?>
<script>
function submitXml() {
    fetch('xxe.php', { method: 'POST', body: document.getElementById('xml').value })
        .then(r => r.text()).then(t => document.open() || document.write(t));
}
</script>
</body>
</html>
