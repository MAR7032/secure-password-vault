<?php

declare(strict_types=1);

session_start();

if (!isset($_SESSION['user_id'], $_SESSION['username'], $_SESSION['user_key'])) {
    header('Location: login.php');
    exit;
}

require_once __DIR__ . '/../classes/Database.php';
require_once __DIR__ . '/../classes/EncryptionService.php';
require_once __DIR__ . '/../classes/User.php';

$config = require __DIR__ . '/../config/database.local.php';

$message = '';
$messageClass = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $currentPassword = $_POST['current_password'] ?? '';
    $newPassword = $_POST['new_password'] ?? '';
    $confirmNewPassword = $_POST['confirm_new_password'] ?? '';

    try {
        $database = new Database($config);

        $user = new User(
            $database->getConnection(),
            new EncryptionService()
        );

        $message = $user->changePassword(
            (int) $_SESSION['user_id'],
            $currentPassword,
            $newPassword,
            $confirmNewPassword
        );

        if ($message === 'Login password changed successfully.') {
            $messageClass = 'success-message';
        } else {
            $messageClass = 'error-message';
        }
    } catch (RuntimeException $exception) {
        $message = 'Password change failed.';
        $messageClass = 'error-message';
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Change Login Password | Secure Password Vault</title>
    <link rel="stylesheet" href="../assets/style.css">
</head>
<body>
    <main class="page-container">
        <section class="card">
            <h1>Secure Password Vault</h1>
            <p class="subtitle">Change login password</p>

            <?php if ($message !== ''): ?>
                <p class="<?php echo $messageClass; ?>">
                    <?php echo htmlspecialchars($message); ?>
                </p>
            <?php endif; ?>

            <form method="post" action="">
                <div class="form-group">
                    <label for="current_password">Current Password</label>
                    <input
                        type="password"
                        id="current_password"
                        name="current_password"
                        required
                    >
                </div>

                <div class="form-group">
                    <label for="new_password">New Password</label>
                    <input
                        type="password"
                        id="new_password"
                        name="new_password"
                        required
                    >
                </div>

                <div class="form-group">
                    <label for="confirm_new_password">Confirm New Password</label>
                    <input
                        type="password"
                        id="confirm_new_password"
                        name="confirm_new_password"
                        required
                    >
                </div>

                <button class="button" type="submit">Change Password</button>
            </form>

            <p class="link-text">
                <a href="dashboard.php">Return to Dashboard</a>
            </p>
        </section>
    </main>
</body>
</html>