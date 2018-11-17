<?php

declare(strict_types=1);

namespace ParagonIE\PasswordLock\Tests;

use Defuse\Crypto\Exception\EnvironmentIsBrokenException;
use Defuse\Crypto\Exception\WrongKeyOrModifiedCiphertextException;
use Defuse\Crypto\Key;
use ParagonIE\PasswordLock\PasswordLock;
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
        $password = $this->lock->lock('YELLOW SUBMARINE');

        $this->assertTrue(
            $this->lock->check('YELLOW SUBMARINE', $password)
        );

        $this->assertFalse(
            $this->lock->check('YELLOW SUBMARINF', $password)
        );
    }

    /**
     * @expectedException \Defuse\Crypto\Exception\WrongKeyOrModifiedCiphertextException
     *
     * @throws EnvironmentIsBrokenException
     */
    public function testBitflip(): void
    {
        $password = $this->lock->lock('YELLOW SUBMARINE');

        $password[0] = (0 === ord($password[0]) ? 255 : 0);

        $this->lock->check('YELLOW SUBMARINE', $password);
    }

    /**
     * @throws EnvironmentIsBrokenException
     */
    public function testNullByteTruncation(): void
    {
        $hash1 = $this->lock->lock("abc\0defg");
        $hash2 = $this->lock->lock("abc");

        $this->assertNotSame($hash1, $hash2);
    }

    /**
     * @throws EnvironmentIsBrokenException
     * @throws WrongKeyOrModifiedCiphertextException
     */
    public function testKeyRotation(): void
    {
        $key1 = Key::createNewRandomKey();
        $lock1 = new PasswordLock($key1);

        $key2 = Key::createNewRandomKey();
        $lock2 = new PasswordLock($key2);

        $hash1 = $lock1->lock('ParagonIE');
        $hash2 = PasswordLock::rotateKey($hash1, $key1, $key2);

        $this->assertNotSame($hash1, $hash2);
        $this->assertTrue($lock2->check('ParagonIE', $hash2));
    }
}
