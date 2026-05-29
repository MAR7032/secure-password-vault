<?php

declare(strict_types=1);

session_start();

require_once __DIR__ . '/../classes/Database.php';
require_once __DIR__ . '/../classes/EncryptionService.php';
require_once __DIR__ . '/../classes/User.php';

$config = require __DIR__ . '/../config/database.local.php';

$message = '';
$username = '';

if (isset($_SESSION['user_id'])) {
    header('Location: dashboard.php');
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';

    try {
        $database = new Database($config);

        $user = new User(
            $database->getConnection(),
            new EncryptionService()
        );

        $authenticatedUser = $user->authenticate($username, $password);

        if ($authenticatedUser !== false) {
            session_regenerate_id(true);

         $_SESSION['user_id'] = $authenticatedUser['id'];
         $_SESSION['username'] = $authenticatedUser['username'];
          $_SESSION['user_key'] = $authenticatedUser['user_key'];

          header('Location: dashboard.php');
            exit;
        }

        $message = 'Invalid username or password.';
    } catch (RuntimeException $exception) {
        $message = 'Database connection failed.';
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Login | Secure Password Vault</title>
    <link rel="stylesheet" href="../assets/style.css">
</head>
<body>
    <main class="page-container">
        <section class="card">
            <h1>Secure Password Vault</h1>
            <p class="subtitle">Login to your account</p>

            <?php if ($message !== ''): ?>
                <p class="error-message">
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

                <button class="button" type="submit">Login</button>
            </form>

            <p class="link-text">
                Need an account? <a href="register.php">Register</a>
            </p>
        </section>
    </main>
</body>
</html>
