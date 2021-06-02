<?php
declare(strict_types=1);
namespace ParagonIE\PasswordLock;

use Defuse\Crypto\Crypto;
use Defuse\Crypto\Exception\EnvironmentIsBrokenException;
use Defuse\Crypto\Exception\WrongKeyOrModifiedCiphertextException;
use Defuse\Crypto\Key;
use ParagonIE\ConstantTime\Base64;
use ParagonIE\ConstantTime\Binary;

/**
 * Class PasswordLock
 * @package ParagonIE\PasswordLock
 */
class PasswordLock
{
    /**
     * @ref https://www.php.net/manual/en/function.password-hash.php
     */
    const OPTIONS_DEFAULT_BCRYPT = ['cost' => 12];
    const OPTIONS_DEFAULT_ARGON2ID = [
        'memory_cost' => 65536,
        'time_cost' => 4,
        'threads' => 1
    ];

    /**
     * 1. Hash password using bcrypt-base64-SHA256
     * 2. Encrypt-then-MAC the hash
     *
     * @param string $password
     * @param Key $aesKey
     * @param ?array $hashOptions
     * @return string
     *
     * @throws EnvironmentIsBrokenException
     * @throws \InvalidArgumentException
     * @psalm-suppress InvalidArgument
     */
    public static function hashAndEncrypt(
        string $password,
        Key $aesKey,
        ?array $hashOptions = null
    ): string {
        if (is_null($hashOptions)) {
            $hashOptions = static::getDefaultOptions();
        }
        if (array_key_exists('salt', $hashOptions)) {
            throw new \InvalidArgumentException('Explicit salts are unsupported.');
        }
        /** @var string $hash */
        $hash = \password_hash(
            Base64::encode(
                \hash('sha384', $password, true)
            ),
            PASSWORD_DEFAULT,
            $hashOptions
        );
        if (!\is_string($hash)) {
            throw new EnvironmentIsBrokenException("Unknown hashing error.");
        }
        return Crypto::encrypt($hash, $aesKey);
    }
    /**
     * 1. VerifyHMAC-then-Decrypt the ciphertext to get the hash
     * 2. Verify that the password matches the hash
     *
     * @param string $password
     * @param string $ciphertext
     * @param string $aesKey - must be exactly 16 bytes
     * @return bool
     *
     * @throws \InvalidArgumentException
     * @throws EnvironmentIsBrokenException
     * @throws WrongKeyOrModifiedCiphertextException
     */
    public static function decryptAndVerifyLegacy(
        string $password,
        string $ciphertext,
        string $aesKey
    ): bool
    {
        if (Binary::safeStrlen($aesKey) !== 16) {
            throw new \InvalidArgumentException("Encryption keys must be 16 bytes long");
        }
        $hash = Crypto::legacyDecrypt(
            $ciphertext,
            $aesKey
        );
        if (!\is_string($hash)) {
            throw new EnvironmentIsBrokenException("Unknown hashing error.");
        }
        return \password_verify(
            Base64::encode(
                \hash('sha256', $password, true)
            ),
            $hash
        );
    }

    /**
     * 1. VerifyHMAC-then-Decrypt the ciphertext to get the hash
     * 2. Verify that the password matches the hash
     *
     * @param string $password
     * @param string $ciphertext
     * @param Key $aesKey
     * @return bool
     *
     * @throws EnvironmentIsBrokenException
     * @throws WrongKeyOrModifiedCiphertextException
     */
    public static function decryptAndVerify(string $password, string $ciphertext, Key $aesKey): bool
    {
        $hash = Crypto::decrypt(
            $ciphertext,
            $aesKey
        );
        if (!\is_string($hash)) {
            throw new EnvironmentIsBrokenException("Unknown hashing error.");
        }
        return \password_verify(
            Base64::encode(
                \hash('sha384', $password, true)
            ),
            $hash
        );
    }

    /**
     * @return array<string, int>
     *
     * @psalm-suppress TypeDoesNotContainType
     */
    protected static function getDefaultOptions(): array
    {
        // Future-proofing:
        if (PASSWORD_DEFAULT === PASSWORD_ARGON2ID) {
            return self::OPTIONS_DEFAULT_ARGON2ID;
        }
        return self::OPTIONS_DEFAULT_BCRYPT;
    }

    /**
     * Decrypt the ciphertext and ascertain if the stored password needs to be rehashed?
     *
     * @param string $ciphertext
     * @param Key $aesKey
     * @param ?array $hashOptions
     * @return bool
     *
     * @throws EnvironmentIsBrokenException
     * @throws WrongKeyOrModifiedCiphertextException
     */
    public static function needsRehash(
        string $ciphertext,
        Key $aesKey,
        ?array $hashOptions = null
    ): bool {
        if (is_null($hashOptions)) {
            $hashOptions = static::getDefaultOptions();
        }
        $hash = Crypto::decrypt(
            $ciphertext,
            $aesKey
        );
        if (!\is_string($hash)) {
            throw new EnvironmentIsBrokenException("Unknown hashing error.");
        }
        /** @psalm-suppress InvalidArgument */
        return password_needs_rehash($hash, PASSWORD_DEFAULT, $hashOptions);
    }

    /**
     * Key rotation method -- decrypt with your old key then re-encrypt with your new key
     *
     * @param string $ciphertext
     * @param  Key $oldKey
     * @param Key $newKey
     * @return string
     *
     * @throws EnvironmentIsBrokenException
     * @throws WrongKeyOrModifiedCiphertextException
     */
    public static function rotateKey(string $ciphertext, Key $oldKey, Key $newKey): string
    {
        $plaintext = Crypto::decrypt($ciphertext, $oldKey);
        return Crypto::encrypt($plaintext, $newKey);
    }

    /**
     * For migrating from an older version of the library
     *
     * @param string $password
     * @param string $ciphertext
     * @param string $oldKey
     * @param Key $newKey
     * @return string
     * @throws \Exception
     */
    public static function upgradeFromVersion1(
        string $password,
        string $ciphertext,
        string $oldKey,
        Key $newKey
    ): string {
        if (!self::decryptAndVerifyLegacy($password, $ciphertext, $oldKey)) {
            throw new \Exception(
                'The correct password is necessary for legacy migration.'
            );
        }
        $plaintext = Crypto::legacyDecrypt($ciphertext, $oldKey);
        return self::hashAndEncrypt($plaintext, $newKey);
    }
}
