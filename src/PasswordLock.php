<?php declare(strict_types=1);
/**
 * PasswordLock - Wraps Bcrypt-SHA2 in Authenticated Encryption.
 *
 * @author Paragon Initiative Enterprises <https://github.com/paragonie>.
 *
 * @license A short and simple permissive license with conditions only requiring preservation of copyright and license notices.
 *          Licensed works, modifications, and larger works may be distributed under different terms and without source code.
 *
 * @link <https://github.com/paragonie/password_lock/blob/master/LICENSE> MIT License.
 * @link <https://github.com/paragonie/password_lock> Source.
 */

namespace ParagonIE\PasswordLock;

use Defuse\Crypto\Crypto;
use Defuse\Crypto\Key;
use ParagonIE\ConstantTime\Base64;
use ParagonIE\ConstantTime\Binary;

class PasswordLock
{

    /**
     * 1. Hash password using bcrypt-base64-SHA256.
     * 2. Encrypt-then-MAC the hash.
     *
     * @param string             $password The password to hash then encrypt.
     * @param \Defuse\Crypto\Key $aesKey   The encryption key to use.
     *
     * @throws \Exception If the hashing error is unknown.
     *
     * @return string Returns the hash and encrypted password.
     */
    public static function hashAndEncrypt(string $password, Key $aesKey): string
    {
        /** @var string $hash */
        $hash = \password_hash(
            Base64::encode(
                \hash('sha384', $password, true)
            ),
            PASSWORD_DEFAULT
        );
        if (!\is_string($hash)) {
            throw new \Exception("Unknown hashing error.");
        }
        return Crypto::encrypt($hash, $aesKey);
    }

    /**
     * 1. VerifyHMAC-then-Decrypt the ciphertext to get the hash.
     * 2. Verify that the password matches the hash.
     *
     * @param string $password   The password to test against.
     * @param string $ciphertext The cipertext to decrypt and verify hash.
     * @param string $aesKey     The encryption key to use. Also note this must be exactly 16 bytes.
     *
     * @throws \Exception If the encryption key is not 16 characters in length. Also is thrown if
     *                    the hashing error is unknown.
     *
     * @return bool Returns true on a valid password and false on failure.
     */
    public static function decryptAndVerifyLegacy(string $password, string $ciphertext, string $aesKey): bool
    {
        if (Binary::safeStrlen($aesKey) !== 16) {
            throw new \Exception("Encryption keys must be 16 bytes long.");
        }
        $hash = Crypto::legacyDecrypt(
            $ciphertext,
            $aesKey
        );
        if (!\is_string($hash)) {
            throw new \Exception("Unknown hashing error.");
        }
        return \password_verify(
            Base64::encode(
                \hash('sha256', $password, true)
            ),
            $hash
        );
    }

    /**
     * 1. VerifyHMAC-then-Decrypt the ciphertext to get the hash.
     * 2. Verify that the password matches the hash.
     *
     * @param string             $password   The password to test against.
     * @param string             $ciphertext The cipertext to decrypt and verify hash.
     * @param \Defuse\Crypto\Key $aesKey     The encryption key to use.
     *
     * @throws \Exception If the hashing error is unknown.
     *
     * @return bool Returns true on a valid password and false on failure.
     */
    public static function decryptAndVerify(string $password, string $ciphertext, Key $aesKey): bool
    {
        $hash = Crypto::decrypt(
            $ciphertext,
            $aesKey
        );
        if (!\is_string($hash)) {
            throw new \Exception("Unknown hashing error.");
        }
        return \password_verify(
            Base64::encode(
                \hash('sha384', $password, true)
            ),
            $hash
        );
    }

    /**
     * Key rotation method -- decrypt with your old key then re-encrypt with your new key.
     *
     * @param string             $ciphertext The cipertext to use.
     * @param \Defuse\Crypto\Key $oldKey     The old encryption key.
     * @param \Defuse\Crypto\Key $newKey     The new encryption key to use.
     *
     * @return string Returns the encrypted ciphertext.
     */
    public static function rotateKey(string $ciphertext, Key $oldKey, Key $newKey): string
    {
        $plaintext = Crypto::decrypt($ciphertext, $oldKey);
        return Crypto::encrypt($plaintext, $newKey);
    }

    /**
     * For migrating from an older version of the library.
     *
     * @param string             $password   The password to use.
     * @param string             $ciphertext The ciphertext to use.
     * @param string             $oldKey     The old encryption key.
     * @param \Defuse\Crypto\Key $newKey     The new encryption key to use.
     *
     * @throws \Exception If the password is invalid.
     *
     * @return string The updated ciphertext.
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
