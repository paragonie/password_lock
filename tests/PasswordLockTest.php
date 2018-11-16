<?php

declare(strict_types=1);

namespace ParagonIE\PasswordLock\Tests;

use Defuse\Crypto\Exception\EnvironmentIsBrokenException;
use Defuse\Crypto\Exception\WrongKeyOrModifiedCiphertextException;
use ParagonIE\PasswordLock\PasswordLock;
use Defuse\Crypto\Key;
use PHPUnit\Framework\TestCase;

use function ord;

/**
 * @backupGlobals disabled
 * @backupStaticAttributes disabled
 */
class PasswordLockTest extends TestCase
{
    /**
     * @var PasswordLock
     */
    protected $lock;

    public function setUp()
    {
        $this->lock = new PasswordLock();
    }

    /**
     * @throws EnvironmentIsBrokenException
     * @throws WrongKeyOrModifiedCiphertextException
     */
    public function testHash(): void
    {
        $key = Key::createNewRandomKey();

        $password = $this->lock->hashAndEncrypt('YELLOW SUBMARINE', $key);
        
        $this->assertTrue(
            $this->lock->decryptAndVerify('YELLOW SUBMARINE', $password, $key)
        );
        
        $this->assertFalse(
            $this->lock->decryptAndVerify('YELLOW SUBMARINF', $password, $key)
        );
    }

    /**
     * @expectedException \Defuse\Crypto\Exception\WrongKeyOrModifiedCiphertextException
     *
     * @throws EnvironmentIsBrokenException
     */
    public function testBitflip(): void
    {
        $key = Key::createNewRandomKey();

        $password = $this->lock->hashAndEncrypt('YELLOW SUBMARINE', $key);

        $password[0] = (ord($password[0]) === 0 ? 255 : 0);
        
        $this->lock->decryptAndVerify('YELLOW SUBMARINE', $password, $key);
    }

    /**
     * @throws EnvironmentIsBrokenException
     */
    public function testNullByteTruncation(): void
    {
        $key = Key::createNewRandomKey();

        $hash1 = $this->lock->hashAndEncrypt("abc\0defg", $key);
        $hash2 = $this->lock->hashAndEncrypt("abc", $key);

        $this->assertNotSame($hash1, $hash2);
    }
}
