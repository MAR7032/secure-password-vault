<?php

declare(strict_types=1);

class User
{
    private PDO $connection;
    private EncryptionService $encryptionService;

    public function __construct(
        PDO $connection,
        EncryptionService $encryptionService
    ) {
        $this->connection = $connection;
        $this->encryptionService = $encryptionService;
    }

    public function register(
        string $username,
        string $password,
        string $confirmPassword
    ): string {
        $username = trim($username);

        if ($username === '' || $password === '' || $confirmPassword === '') {
            return 'All fields are required.';
        }

        if (strlen($username) < 3 || strlen($username) > 50) {
            return 'Username must be between 3 and 50 characters.';
        }

        if (strlen($password) < 8) {
            return 'Password must contain at least 8 characters.';
        }

        if ($password !== $confirmPassword) {
            return 'Passwords do not match.';
        }

        $checkStatement = $this->connection->prepare(
            'SELECT id FROM users WHERE username = :username'
        );

        $checkStatement->execute([
            'username' => $username
        ]);

        if ($checkStatement->fetch() !== false) {
            return 'This username is already registered.';
        }

        $passwordHash = password_hash($password, PASSWORD_DEFAULT);

        if ($passwordHash === false) {
            return 'Account creation failed.';
        }

        try {
            $encryptedUserKey = $this->encryptionService
                ->createEncryptedUserKey($password);

            $insertStatement = $this->connection->prepare(
                'INSERT INTO users (
                    username,
                    password_hash,
                    encrypted_key,
                    key_iv,
                    key_tag,
                    key_salt
                ) VALUES (
                    :username,
                    :password_hash,
                    :encrypted_key,
                    :key_iv,
                    :key_tag,
                    :key_salt
                )'
            );

            $insertStatement->execute([
                'username' => $username,
                'password_hash' => $passwordHash,
                'encrypted_key' => $encryptedUserKey['encrypted_key'],
                'key_iv' => $encryptedUserKey['key_iv'],
                'key_tag' => $encryptedUserKey['key_tag'],
                'key_salt' => $encryptedUserKey['key_salt']
            ]);
        } catch (Throwable $exception) {
            return 'Account creation failed.';
        }

        return 'Account created successfully.';
    }

    public function authenticate(string $username, string $password): array|false
    {
        $username = trim($username);

        if ($username === '' || $password === '') {
            return false;
        }

        $statement = $this->connection->prepare(
            'SELECT
                id,
                username,
                password_hash,
                encrypted_key,
                key_iv,
                key_tag,
                key_salt
             FROM users
             WHERE username = :username'
        );

        $statement->execute([
            'username' => $username
        ]);

        $user = $statement->fetch();

        if ($user === false) {
            return false;
        }

        if (!password_verify($password, $user['password_hash'])) {
            return false;
        }

        try {
            $userKey = $this->encryptionService->decryptUserKey(
                $password,
                [
                    'encrypted_key' => $user['encrypted_key'],
                    'key_iv' => $user['key_iv'],
                    'key_tag' => $user['key_tag'],
                    'key_salt' => $user['key_salt']
                ]
            );
        } catch (RuntimeException $exception) {
            return false;
        }

        return [
            'id' => (int) $user['id'],
            'username' => $user['username'],
            'user_key' => base64_encode($userKey)
        ];
    }

    public function changePassword(
        int $userId,
        string $currentPassword,
        string $newPassword,
        string $confirmNewPassword
    ): string {
        if (
            $currentPassword === '' ||
            $newPassword === '' ||
            $confirmNewPassword === ''
        ) {
            return 'All fields are required.';
        }

        if (strlen($newPassword) < 8) {
            return 'New password must contain at least 8 characters.';
        }

        if ($newPassword !== $confirmNewPassword) {
            return 'New passwords do not match.';
        }

        if ($currentPassword === $newPassword) {
            return 'New password must be different from the current password.';
        }

        $statement = $this->connection->prepare(
            'SELECT
                password_hash,
                encrypted_key,
                key_iv,
                key_tag,
                key_salt
             FROM users
             WHERE id = :id'
        );

        $statement->execute([
            'id' => $userId
        ]);

        $user = $statement->fetch();

        if ($user === false) {
            return 'User account was not found.';
        }

        if (!password_verify($currentPassword, $user['password_hash'])) {
            return 'Current password is incorrect.';
        }

        try {
            $sameUserKey = $this->encryptionService->decryptUserKey(
                $currentPassword,
                [
                    'encrypted_key' => $user['encrypted_key'],
                    'key_iv' => $user['key_iv'],
                    'key_tag' => $user['key_tag'],
                    'key_salt' => $user['key_salt']
                ]
            );

            $newPasswordHash = password_hash($newPassword, PASSWORD_DEFAULT);

            if ($newPasswordHash === false) {
                return 'Password change failed.';
            }

            $reencryptedKey = $this->encryptionService->encryptExistingUserKey(
                $sameUserKey,
                $newPassword
            );

            $this->connection->beginTransaction();

            $updateStatement = $this->connection->prepare(
                'UPDATE users
                 SET
                    password_hash = :password_hash,
                    encrypted_key = :encrypted_key,
                    key_iv = :key_iv,
                    key_tag = :key_tag,
                    key_salt = :key_salt
                 WHERE id = :id'
            );

            $updateStatement->execute([
                'password_hash' => $newPasswordHash,
                'encrypted_key' => $reencryptedKey['encrypted_key'],
                'key_iv' => $reencryptedKey['key_iv'],
                'key_tag' => $reencryptedKey['key_tag'],
                'key_salt' => $reencryptedKey['key_salt'],
                'id' => $userId
            ]);

            $this->connection->commit();
        } catch (Throwable $exception) {
            if ($this->connection->inTransaction()) {
                $this->connection->rollBack();
            }

            return 'Password change failed.';
        }

        return 'Login password changed successfully.';
    }
}