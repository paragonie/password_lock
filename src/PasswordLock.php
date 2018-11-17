<?php

declare(strict_types=1);

namespace ParagonIE\PasswordLock;

use Defuse\Crypto\Crypto;
use Defuse\Crypto\Exception\EnvironmentIsBrokenException;
use Defuse\Crypto\Exception\WrongKeyOrModifiedCiphertextException;
use Defuse\Crypto\Key;
use ParagonIE\PasswordLock\Hasher\PasswordHasher;
use ParagonIE\PasswordLock\Hasher\PasswordHasherInterface;

class PasswordLock
{
    /**
     * @var Key
     */
    protected $key;

    /**
     * @var PasswordHasherInterface
     */
    protected $hasher;


    public function __construct(Key $key,PasswordHasherInterface $hasher = null)
    {
        $this->key = $key;
        $this->hasher = $hasher ?? new PasswordHasher();
    }

    /**
     * 1. Hash password
     * 2. Encrypt-then-MAC the hash
     *
     * @throws EnvironmentIsBrokenException
     */
    public function lock(string $password): string
    {
        $hash = $this->hasher->hash($password);

        return Crypto::encrypt($hash, $this->key);
    }

    /**
     * 1. VerifyHMAC-then-Decrypt the ciphertext to get the hash
     * 2. Verify that the password matches the hash
     *
     * @throws EnvironmentIsBrokenException
     * @throws WrongKeyOrModifiedCiphertextException
     */
    public function check(string $password, string $ciphertext): bool
    {
        $hash = Crypto::decrypt(
            $ciphertext,
            $this->key
        );

        return $this->hasher->verify($password, $hash);
    }

    /**
     * Key rotation method -- decrypt with your old key then re-encrypt with your new key
     *
     * @throws EnvironmentIsBrokenException
     * @throws WrongKeyOrModifiedCiphertextException
     */
    public static function rotateKey(string $ciphertext, Key $oldKey, Key $newKey): string
    {
        $plaintext = Crypto::decrypt($ciphertext, $oldKey);
        return Crypto::encrypt($plaintext, $newKey);
    }
}
