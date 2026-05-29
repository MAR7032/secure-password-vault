<?php

declare(strict_types=1);

$pageTitle = 'Secure Password Vault';
$message = 'Store your password records safely and securely.';
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title><?php echo htmlspecialchars($pageTitle); ?></title>
    <link rel="stylesheet" href="../assets/style.css">
</head>
<body>
    <main class="page-container">
        <section class="card">
            <h1><?php echo htmlspecialchars($pageTitle); ?></h1>
            <p class="subtitle"><?php echo htmlspecialchars($message); ?></p>

            <a class="button" href="register.php">Create Account</a>

            <p class="link-text">
                Database connection test: 
                <a href="test_connection.php">Open test page</a>
            </p>
        </section>
    </main>
</body>
</html>