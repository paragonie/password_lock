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
        $key = \hex2bin('0102030405060708090a0b0c0d0e0f10');
        $password = PasswordLock::hashAndEncrypt('YELLOW SUBMARINE', $key);
        
        $this->assertTrue(
            PasswordLock::decryptAndVerify('YELLOW SUBMARINE', $password, $key)
        );
    }
}
