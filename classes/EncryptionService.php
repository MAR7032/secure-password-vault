<?php

declare(strict_types=1);

class EncryptionService
{
    private const CIPHER = 'aes-256-gcm';
    private const KEY_LENGTH = 32;
    private const SALT_LENGTH = 16;
    private const ITERATIONS = 100000;

    public function createEncryptedUserKey(string $plainPassword): array
    {
        $userKey = random_bytes(self::KEY_LENGTH);
        $salt = random_bytes(self::SALT_LENGTH);
        $iv = random_bytes(openssl_cipher_iv_length(self::CIPHER));

        $derivedKey = hash_pbkdf2(
            'sha256',
            $plainPassword,
            $salt,
            self::ITERATIONS,
            self::KEY_LENGTH,
            true
        );

        $tag = '';

        $encryptedKey = openssl_encrypt(
            $userKey,
            self::CIPHER,
            $derivedKey,
            OPENSSL_RAW_DATA,
            $iv,
            $tag
        );

        if ($encryptedKey === false) {
            throw new RuntimeException('Encryption failed.');
        }

        return [
            'encrypted_key' => base64_encode($encryptedKey),
            'key_iv' => base64_encode($iv),
            'key_tag' => base64_encode($tag),
            'key_salt' => base64_encode($salt)
        ];
    }
}
