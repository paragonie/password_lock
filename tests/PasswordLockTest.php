<?php
use \ParagonIE\PasswordLock\PasswordLock;
/**
 * @backupGlobals disabled
 * @backupStaticAttributes disabled
 */
class PasswordLockTest extends PHPUnit_Framework_TestCase
{
    public function testHash()
    {
        $key = \Defuse\Crypto\Key::createNewRandomKey();

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
        $key = \Defuse\Crypto\Key::createNewRandomKey();
        $password = PasswordLock::hashAndEncrypt('YELLOW SUBMARINE', $key);
        $password[0] = (\ord($password[0]) === 0 ? 255 : 0);
        
        PasswordLock::decryptAndVerify('YELLOW SUBMARINE', $password, $key);
    }
}
