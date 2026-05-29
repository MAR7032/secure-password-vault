<?php

declare(strict_types=1);

require_once __DIR__ . '/../classes/Database.php';
require_once __DIR__ . '/../classes/EncryptionService.php';
require_once __DIR__ . '/../classes/User.php';

$config = require __DIR__ . '/../config/database.local.php';

$pageTitle = 'Create Account';
$message = '';
$messageClass = '';
$username = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';
    $confirmPassword = $_POST['confirm_password'] ?? '';

    try {
        $database = new Database($config);
        $encryptionService = new EncryptionService();
        $user = new User(
            $database->getConnection(),
            $encryptionService
        );

        $message = $user->register(
            $username,
            $password,
            $confirmPassword
        );

        if ($message === 'Account created successfully.') {
            $messageClass = 'success-message';
            $username = '';
        } else {
            $messageClass = 'error-message';
        }
    } catch (RuntimeException $exception) {
        $message = 'Database connection failed.';
        $messageClass = 'error-message';
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title><?php echo htmlspecialchars($pageTitle); ?> | Secure Password Vault</title>
    <link rel="stylesheet" href="../assets/style.css">
</head>
<body>
    <main class="page-container">
        <section class="card">
            <h1>Secure Password Vault</h1>
            <p class="subtitle">Create your account</p>

            <?php if ($message !== ''): ?>
                <p class="<?php echo $messageClass; ?>">
                    <?php echo htmlspecialchars($message); ?>
                </p>
            <?php endif; ?>

            <form method="post" action="">
                <div class="form-group">
                    <label for="username">Username</label>
                    <input
                        type="text"
                        id="username"
                        name="username"
                        value="<?php echo htmlspecialchars($username); ?>"
                        required
                    >
                </div>

                <div class="form-group">
                    <label for="password">Password</label>
                    <input
                        type="password"
                        id="password"
                        name="password"
                        required
                    >
                </div>

                <div class="form-group">
                    <label for="confirm_password">Confirm Password</label>
                    <input
                        type="password"
                        id="confirm_password"
                        name="confirm_password"
                        required
                    >
                </div>

                <button class="button" type="submit">Create Account</button>
            </form>

            <p class="link-text">
                Already have an account? <a href="#">Login</a>
            </p>
        </section>
    </main>
</body>
</html>