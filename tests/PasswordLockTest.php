<?php
use \ParagonIE\PasswordLock;
/**
 * @backupGlobals disabled
 * @backupStaticAttributes disabled
 */
class PasswordLockTest extends PHPUnit_Framework_TestCase
{
    public function testHash()
    {
        $key = \hex2bin('000102030405060708090a0b0c0d0e');
        $password = PasswordLock::hashAndEncrypt('YELLOW SUBMARINE', $key);
        
        $this->assertTrue(
            PasswordLock::decryptAndVerify('YELLOW SUBMARINE', $password, $key)
        );
    }
}
