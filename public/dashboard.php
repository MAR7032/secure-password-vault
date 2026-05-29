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

            <p class="link-text">
                Password storage features will be added in the next version.
            </p>

            <a class="button" href="logout.php">Logout</a>
        </section>
    </main>
</body>
</html>