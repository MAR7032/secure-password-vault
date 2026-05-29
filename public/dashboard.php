<?php

declare(strict_types=1);

session_start();

if (!isset($_SESSION['user_id'], $_SESSION['username'])) {
    header('Location: login.php');
    exit;
}

$username = $_SESSION['username'];
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Dashboard | Secure Password Vault</title>
    <link rel="stylesheet" href="../assets/style.css">
</head>
<body>
    <main class="page-container">
        <section class="card">
            <h1>Secure Password Vault</h1>

            <p class="subtitle">
                Welcome, <?php echo htmlspecialchars($username); ?>.
            </p>

            <p>Your account login is working successfully.</p>

            <a class="button" href="add_password.php">Add Password Record</a>

             <a class="button secondary-button" href="view_passwords.php">View Saved Passwords</a>
             <a class="button secondary-button" href="generate_password.php">Generate Password</a>

            <a class="button secondary-button" href="change_password.php">Change Login Password</a>

             <p class="link-text">
                       Encrypted password storage is available.
            </p>

          <a class="button secondary-button" href="logout.php">Logout</a>
        </section>
    </main>
</body>
</html>