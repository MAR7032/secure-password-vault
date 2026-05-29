<?php

declare(strict_types=1);

session_start();

if (!isset($_SESSION['user_id'], $_SESSION['username'])) {
    header('Location: login.php');
    exit;
}

require_once __DIR__ . '/../classes/PasswordGenerator.php';

$message = '';
$generatedPassword = '';

$length = 12;
$lowercaseCount = 3;
$uppercaseCount = 3;
$numberCount = 3;
$specialCount = 3;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $length = (int) ($_POST['length'] ?? 12);
    $lowercaseCount = (int) ($_POST['lowercase_count'] ?? 0);
    $uppercaseCount = (int) ($_POST['uppercase_count'] ?? 0);
    $numberCount = (int) ($_POST['number_count'] ?? 0);
    $specialCount = (int) ($_POST['special_count'] ?? 0);

    try {
        $generator = new PasswordGenerator();

        $generatedPassword = $generator->generate(
            $length,
            $lowercaseCount,
            $uppercaseCount,
            $numberCount,
            $specialCount
        );
    } catch (InvalidArgumentException $exception) {
        $message = $exception->getMessage();
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Password Generator | Secure Password Vault</title>
    <link rel="stylesheet" href="../assets/style.css">
</head>
<body>
    <main class="page-container">
        <section class="card generator-card">
            <h1>Password Generator</h1>
            <p class="subtitle">Choose exactly how many characters to include</p>

            <?php if ($message !== ''): ?>
                <p class="error-message">
                    <?php echo htmlspecialchars($message); ?>
                </p>
            <?php endif; ?>

            <?php if ($generatedPassword !== ''): ?>
                <div class="generated-result">
                    <label>Generated Password</label>
                    <code><?php echo htmlspecialchars($generatedPassword); ?></code>
                    <p class="result-note">
                        Copy this test password into the Add Password form to save it.
                    </p>
                </div>
            <?php endif; ?>

            <form method="post" action="">
                <div class="form-group">
                    <label for="length">Total Length</label>
                    <input
                        type="number"
                        id="length"
                        name="length"
                        min="4"
                        max="100"
                        value="<?php echo $length; ?>"
                        required
                    >
                </div>

                <div class="generator-grid">
                    <div class="form-group">
                        <label for="lowercase_count">Lowercase</label>
                        <input
                            type="number"
                            id="lowercase_count"
                            name="lowercase_count"
                            min="0"
                            value="<?php echo $lowercaseCount; ?>"
                            required
                        >
                    </div>

                    <div class="form-group">
                        <label for="uppercase_count">Uppercase</label>
                        <input
                            type="number"
                            id="uppercase_count"
                            name="uppercase_count"
                            min="0"
                            value="<?php echo $uppercaseCount; ?>"
                            required
                        >
                    </div>

                    <div class="form-group">
                        <label for="number_count">Numbers</label>
                        <input
                            type="number"
                            id="number_count"
                            name="number_count"
                            min="0"
                            value="<?php echo $numberCount; ?>"
                            required
                        >
                    </div>

                    <div class="form-group">
                        <label for="special_count">Special Characters</label>
                        <input
                            type="number"
                            id="special_count"
                            name="special_count"
                            min="0"
                            value="<?php echo $specialCount; ?>"
                            required
                        >
                    </div>
                </div>

                <button class="button" type="submit">Generate Password</button>
            </form>

            <p class="link-text">
                <a href="dashboard.php">Return to Dashboard</a>
            </p>
        </section>
    </main>
</body>
</html>