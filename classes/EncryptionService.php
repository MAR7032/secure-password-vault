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

        $derivedKey = $this->deriveKey($plainPassword, $salt);
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

    public function decryptUserKey(
        string $plainPassword,
        array $storedKeyData
    ): string {
        $encryptedKey = $this->decodeValue($storedKeyData['encrypted_key']);
        $iv = $this->decodeValue($storedKeyData['key_iv']);
        $tag = $this->decodeValue($storedKeyData['key_tag']);
        $salt = $this->decodeValue($storedKeyData['key_salt']);

        $derivedKey = $this->deriveKey($plainPassword, $salt);

        $userKey = openssl_decrypt(
            $encryptedKey,
            self::CIPHER,
            $derivedKey,
            OPENSSL_RAW_DATA,
            $iv,
            $tag
        );

        if ($userKey === false) {
            throw new RuntimeException('Unable to unlock the user key.');
        }

        return $userKey;
    }

    public function encryptExistingUserKey(
        string $userKey,
        string $newPlainPassword
    ): array {
        $salt = random_bytes(self::SALT_LENGTH);
        $iv = random_bytes(openssl_cipher_iv_length(self::CIPHER));

        $derivedKey = $this->deriveKey($newPlainPassword, $salt);
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
            throw new RuntimeException('Key encryption failed.');
        }

        return [
            'encrypted_key' => base64_encode($encryptedKey),
            'key_iv' => base64_encode($iv),
            'key_tag' => base64_encode($tag),
            'key_salt' => base64_encode($salt)
        ];
    }

    public function encryptStoredPassword(
        string $plainPassword,
        string $userKey
    ): array {
        $iv = random_bytes(openssl_cipher_iv_length(self::CIPHER));
        $tag = '';

        $encryptedPassword = openssl_encrypt(
            $plainPassword,
            self::CIPHER,
            $userKey,
            OPENSSL_RAW_DATA,
            $iv,
            $tag
        );

        if ($encryptedPassword === false) {
            throw new RuntimeException('Password encryption failed.');
        }

        return [
            'encrypted_password' => base64_encode($encryptedPassword),
            'password_iv' => base64_encode($iv),
            'password_tag' => base64_encode($tag)
        ];
    }

    public function decryptStoredPassword(
        string $encryptedPassword,
        string $passwordIv,
        string $passwordTag,
        string $userKey
    ): string {
        $encryptedValue = $this->decodeValue($encryptedPassword);
        $iv = $this->decodeValue($passwordIv);
        $tag = $this->decodeValue($passwordTag);

        $plainPassword = openssl_decrypt(
            $encryptedValue,
            self::CIPHER,
            $userKey,
            OPENSSL_RAW_DATA,
            $iv,
            $tag
        );

        if ($plainPassword === false) {
            throw new RuntimeException('Password decryption failed.');
        }

        return $plainPassword;
    }

    private function deriveKey(string $plainPassword, string $salt): string
    {
        return hash_pbkdf2(
            'sha256',
            $plainPassword,
            $salt,
            self::ITERATIONS,
            self::KEY_LENGTH,
            true
        );
    }

    private function decodeValue(string $encodedValue): string
    {
        $decodedValue = base64_decode($encodedValue, true);

        if ($decodedValue === false) {
            throw new RuntimeException('Stored encrypted data is invalid.');
        }

        return $decodedValue;
    }
}