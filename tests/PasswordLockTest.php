<?php
declare(strict_types=1);

use ParagonIE\PasswordLock\PasswordLock;
use Defuse\Crypto\Key;
use PHPUnit\Framework\TestCase;
use Defuse\Crypto\Exception\WrongKeyOrModifiedCiphertextException;

/**
 * @backupGlobals disabled
 * @backupStaticAttributes disabled
 */
class PasswordLockTest extends TestCase
{
    public function testHash()
    {
        $key = Key::createNewRandomKey();

        $password = PasswordLock::hashAndEncrypt('YELLOW SUBMARINE', $key);
        
        $this->assertTrue(
            PasswordLock::decryptAndVerify('YELLOW SUBMARINE', $password, $key)
        );
        
        $this->assertFalse(
            PasswordLock::decryptAndVerify('YELLOW SUBMARINF', $password, $key)
        );
    }

    public function testBitflip()
    {
        $failed = false;
        try {
            $key = Key::createNewRandomKey();
            $password = PasswordLock::hashAndEncrypt('YELLOW SUBMARINE', $key);
            $password[0] = (\ord($password[0]) === 0 ? 255 : 0);

            PasswordLock::decryptAndVerify('YELLOW SUBMARINE', $password, $key);
        } catch (WrongKeyOrModifiedCiphertextException $ex) {
            $failed = true;
        }
        $this->assertTrue($failed, 'Bitflips should break the decryption');
    }

    public function testNeedsRehash()
    {
        $lowCost = ['cost' => 8];
        $key = Key::createNewRandomKey();
        $password = PasswordLock::hashAndEncrypt('YELLOW SUBMARINE', $key, $lowCost);
        $this->assertTrue(PasswordLock::needsRehash($password, $key));
        $this->assertFalse(PasswordLock::needsRehash($password, $key, $lowCost));
    }
}
