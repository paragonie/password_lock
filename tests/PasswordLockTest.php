<?php
declare(strict_types=1);
use \ParagonIE\PasswordLock\PasswordLock;
use \Defuse\Crypto\Key;
/**
 * @backupGlobals disabled
 * @backupStaticAttributes disabled
 */
class PasswordLockTest extends PHPUnit_Framework_TestCase
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
    
    /**
     * @expectedException \Defuse\Crypto\Exception\WrongKeyOrModifiedCiphertextException
     */
    public function testBitflip()
    {
        $key = Key::createNewRandomKey();
        $password = PasswordLock::hashAndEncrypt('YELLOW SUBMARINE', $key);
        $password[0] = (\ord($password[0]) === 0 ? 255 : 0);
        
        PasswordLock::decryptAndVerify('YELLOW SUBMARINE', $password, $key);
    }
}
