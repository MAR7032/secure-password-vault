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
$messageClass = '';
$serviceName = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $serviceName = $_POST['service_name'] ?? '';
    $passwordToSave = $_POST['password_to_save'] ?? '';

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

        $message = $passwordRecord->save(
            (int) $_SESSION['user_id'],
            $serviceName,
            $passwordToSave,
            $userKey
        );

        if ($message === 'Password record saved securely.') {
            $messageClass = 'success-message';
            $serviceName = '';
        } else {
            $messageClass = 'error-message';
        }
    } catch (RuntimeException $exception) {
        $message = 'Password record could not be saved.';
        $messageClass = 'error-message';
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Add Password | Secure Password Vault</title>
    <link rel="stylesheet" href="../assets/style.css">
</head>
<body>
    <main class="page-container">
        <section class="card">
            <h1>Secure Password Vault</h1>
            <p class="subtitle">Add a password record</p>

            <?php if ($message !== ''): ?>
                <p class="<?php echo $messageClass; ?>">
                    <?php echo htmlspecialchars($message); ?>
                </p>
            <?php endif; ?>

            <form method="post" action="">
                <div class="form-group">
                    <label for="service_name">Website or Program Name</label>
                    <input
                        type="text"
                        id="service_name"
                        name="service_name"
                        value="<?php echo htmlspecialchars($serviceName); ?>"
                        placeholder="Example: Gmail"
                        required
                    >
                </div>

                <div class="form-group">
                    <label for="password_to_save">Password to Save</label>
                    <input
                        type="password"
                        id="password_to_save"
                        name="password_to_save"
                        required
                    >
                </div>

                <button class="button" type="submit">Save Securely</button>
            </form>

            <p class="link-text">
                <a href="dashboard.php">Return to Dashboard</a>
            </p>
        </section>
    </main>
</body>
</html>