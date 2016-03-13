<?php
namespace ParagonIE\PasswordLock;

use \Defuse\Crypto\Crypto;
use \Defuse\Crypto\Key;
use \ParagonIE\ConstantTime\Base64;

class PasswordLock
{
    /**
     * 1. Hash password using bcrypt-base64-SHA256
     * 2. Encrypt-then-MAC the hash
     *
     * @param string $password
     * @param Key $aesKey
     * @return string
     */
    public static function hashAndEncrypt($password, Key $aesKey)
    {
        if (!\is_string($password)) {
            throw new \InvalidArgumentException(
                'Password must be a string.'
            );
        }
        $hash = \password_hash(
            Base64::encode(
                \hash('sha384', $password, true)
            ),
            PASSWORD_DEFAULT
        );
        if ($hash === false) {
            throw new \Exception("Unknown hashing error.");
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
     * @return boolean
     */
    public static function decryptAndVerifyLegacy($password, $ciphertext, $aesKey)
    {
        if (!\is_string($password)) {
            throw new \InvalidArgumentException(
                'Password must be a string.'
            );
        }
        if (self::safeStrlen($aesKey) !== 16) {
            throw new \Exception("Encryption keys must be 16 bytes long");
        }
        $hash = Crypto::legacyDecrypt(
            $ciphertext,
            $aesKey
        );
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
     * @return boolean
     */
    public static function decryptAndVerify($password, $ciphertext, Key $aesKey)
    {
        if (!\is_string($password)) {
            throw new \InvalidArgumentException(
                'Password must be a string.'
            );
        }
        if (!\is_string($ciphertext)) {
            throw new \InvalidArgumentException(
                'Ciphertext must be a string.'
            );
        }
        if (self::safeStrlen($aesKey) !== 32) {
            throw new \Exception("Encryption keys must be 32 bytes long");
        }
        $hash = Crypto::decrypt(
            $ciphertext,
            $aesKey
        );
        return \password_verify(
            Base64::encode(
                \hash('sha384', $password, true)
            ),
            $hash
        );
    }
    
    /**
     * Key rotation method -- decrypt with your old key then re-encrypt with your new key
     * 
     * @param string $ciphertext
     * @param  Key $oldKey
     * @param Key $newKey
     * @return string
     */
    public static function rotateKey($ciphertext, Key $oldKey, Key $newKey)
    {
        $plaintext = Crypto::decrypt($ciphertext, $oldKey);
        return Crypto::encrypt($plaintext, $newKey);
    }
    
    /**
     * For migrating from an older version of the library
     * 
     * @param string $password
     * @param string $ciphertext
     * @param sring $oldKey
     * @param Key $newKey
     * @return string
     */
    public static function upgradeFromVersion1(
        $password,
        $ciphertext,
        $oldKey,
        Key $newKey
    ) {
        if (!self::decryptAndVerifyLegacy($password, $ciphertext, $oldKey)) {
            throw new \Exception(
                'The correct password is necessary for legacy migration.'
            );
        }
        $plaintext = Crypto::legacyDecrypt($ciphertext, $oldKey);
        return self::hashAndEncrypt($password, $newKey);
    }

    /**
     * Don't count characters, count the number of bytes
     *
     * @param string
     * @return int
     */
    protected static function safeStrlen($str)
    {
        static $exists = null;
        if ($exists === null) {
            $exists = \function_exists('\\mb_strlen');
        }
        if ($exists) {
            return \mb_strlen($str, '8bit');
        }
        return \strlen($str);
    }
}
