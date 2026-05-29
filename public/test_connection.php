<?php

declare(strict_types=1);

require_once __DIR__ . '/../classes/Database.php';

$config = require __DIR__ . '/../config/database.local.php';

$message = '';
$tableCount = 0;

try {
    $database = new Database($config);
    $connection = $database->getConnection();

    $query = $connection->query(
        "SELECT COUNT(*) 
         FROM information_schema.tables 
         WHERE table_schema = DATABASE()"
    );

    $tableCount = (int) $query->fetchColumn();
    $message = 'Database connection is working.';
} catch (RuntimeException $exception) {
    $message = 'Database connection failed.';
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Database Connection Test</title>
</head>
<body>
    <h1>Secure Password Vault</h1>
    <h2><?php echo htmlspecialchars($message); ?></h2>

    <?php if ($tableCount > 0): ?>
        <p>Tables found in database: <?php echo $tableCount; ?></p>
    <?php endif; ?>
</body>
</html>