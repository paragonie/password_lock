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

    /**
     * @throws EnvironmentIsBrokenException
     */
    public function setUp()
    {
        $this->lock = new PasswordLock(
            Key::createNewRandomKey()
        );
    }


    /**
     * @throws EnvironmentIsBrokenException
     * @throws WrongKeyOrModifiedCiphertextException
     */
    public function testHash(): void
    {
        $password = $this->lock->hashAndEncrypt('YELLOW SUBMARINE');

        $this->assertTrue(
            $this->lock->decryptAndVerify('YELLOW SUBMARINE', $password)
        );
        
        $this->assertFalse(
            $this->lock->decryptAndVerify('YELLOW SUBMARINF', $password)
        );
    }

    /**
     * @expectedException \Defuse\Crypto\Exception\WrongKeyOrModifiedCiphertextException
     *
     * @throws EnvironmentIsBrokenException
     */
    public function testBitflip(): void
    {
        $password = $this->lock->hashAndEncrypt('YELLOW SUBMARINE');

        $password[0] = (ord($password[0]) === 0 ? 255 : 0);
        
        $this->lock->decryptAndVerify('YELLOW SUBMARINE', $password);
    }

    /**
     * @throws EnvironmentIsBrokenException
     */
    public function testNullByteTruncation(): void
    {
        $hash1 = $this->lock->hashAndEncrypt("abc\0defg");
        $hash2 = $this->lock->hashAndEncrypt("abc");

        $this->assertNotSame($hash1, $hash2);
    }
}
