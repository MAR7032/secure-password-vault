<?php

declare(strict_types=1);

class PasswordRecord
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

    public function save(
        int $userId,
        string $serviceName,
        string $plainPassword,
        string $userKey
    ): string {
        $serviceName = trim($serviceName);

        if ($serviceName === '' || $plainPassword === '') {
            return 'Service name and password are required.';
        }

        if (strlen($serviceName) > 100) {
            return 'Service name must not exceed 100 characters.';
        }

        try {
            $encryptedData = $this->encryptionService->encryptStoredPassword(
                $plainPassword,
                $userKey
            );

            $statement = $this->connection->prepare(
                'INSERT INTO password_records (
                    user_id,
                    service_name,
                    encrypted_password,
                    password_iv,
                    password_tag
                ) VALUES (
                    :user_id,
                    :service_name,
                    :encrypted_password,
                    :password_iv,
                    :password_tag
                )'
            );

            $statement->execute([
                'user_id' => $userId,
                'service_name' => $serviceName,
                'encrypted_password' => $encryptedData['encrypted_password'],
                'password_iv' => $encryptedData['password_iv'],
                'password_tag' => $encryptedData['password_tag']
            ]);
        } catch (Throwable $exception) {
            return 'Password record could not be saved.';
        }

        return 'Password record saved securely.';
    }
        public function findAllForUser(int $userId, string $userKey): array
    {
        $statement = $this->connection->prepare(
            'SELECT
                id,
                service_name,
                encrypted_password,
                password_iv,
                password_tag,
                created_at
             FROM password_records
             WHERE user_id = :user_id
             ORDER BY created_at DESC'
        );

        $statement->execute([
            'user_id' => $userId
        ]);

        $records = $statement->fetchAll();
        $decryptedRecords = [];

        foreach ($records as $record) {
            $decryptedRecords[] = [
                'id' => (int) $record['id'],
                'service_name' => $record['service_name'],
                'password' => $this->encryptionService->decryptStoredPassword(
                    $record['encrypted_password'],
                    $record['password_iv'],
                    $record['password_tag'],
                    $userKey
                ),
                'created_at' => $record['created_at']
            ];
        }

        return $decryptedRecords;
    }
}