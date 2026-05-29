<?php

declare(strict_types=1);

session_start();

if (!isset($_SESSION['user_id'], $_SESSION['username'], $_SESSION['user_key'])) {
    header('Location: login.php');
    exit;
}

require_once __DIR__ . '/../classes/Database.php';
require_once __DIR__ . '/../classes/EncryptionService.php';
require_once __DIR__ . '/../classes/PasswordRecord.php';

$config = require __DIR__ . '/../config/database.local.php';

$message = '';
$records = [];

try {
    $database = new Database($config);

    $passwordRecord = new PasswordRecord(
        $database->getConnection(),
        new EncryptionService()
    );

    $userKey = base64_decode($_SESSION['user_key'], true);

    if ($userKey === false) {
        throw new RuntimeException('Session key is invalid.');
    }

    $records = $passwordRecord->findAllForUser(
        (int) $_SESSION['user_id'],
        $userKey
    );
} catch (Throwable $exception) {
    $message = 'Saved password records could not be displayed.';
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Saved Passwords | Secure Password Vault</title>
    <link rel="stylesheet" href="../assets/style.css">
</head>
<body>
    <main class="records-container">
        <section class="records-card">
            <div class="records-header">
                <div>
                    <h1>Saved Passwords</h1>
                    <p>Encrypted records for <?php echo htmlspecialchars($_SESSION['username']); ?></p>
                </div>

                <a class="small-button" href="dashboard.php">Dashboard</a>
            </div>

            <?php if ($message !== ''): ?>
                <p class="error-message">
                    <?php echo htmlspecialchars($message); ?>
                </p>
            <?php elseif (count($records) === 0): ?>
                <p class="empty-message">No password records saved yet.</p>
            <?php else: ?>
                <table class="records-table">
                    <thead>
                        <tr>
                            <th>Website / Program</th>
                            <th>Saved Password</th>
                            <th>Date and Time</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($records as $record): ?>
                            <tr>
                                <td><?php echo htmlspecialchars($record['service_name']); ?></td>
                                <td>
                                    <code><?php echo htmlspecialchars($record['password']); ?></code>
                                </td>
                                <td><?php echo htmlspecialchars($record['created_at']); ?></td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            <?php endif; ?>

            <p class="link-text">
                <a href="add_password.php">Add Another Password</a>
            </p>
        </section>
    </main>
</body>
</html>