<?php

declare(strict_types=1);

namespace ParagonIE\PasswordLock\Tests\Hasher;

use ParagonIE\PasswordLock\Hasher\PasswordHasher;
use PHPUnit\Framework\TestCase;

class PasswordHasherTest extends TestCase
{
    protected $hasher;

    public function setUp()
    {
        $this->hasher = new PasswordHasher();
    }

    public function testHash(): void
    {
        $hash = $this->hasher->hash('RED AIRPLANE');

        $this->assertTrue(
            $this->hasher->verify('RED AIRPLANE', $hash)
        );

        $this->assertFalse(
            $this->hasher->verify('RED AiRPLANE', $hash)
        );
    }

    public function testDefaultParameters(): void
    {
        $this->assertEquals(
            PASSWORD_DEFAULT,
            $this->hasher->getAlgorithm()
        );

        $this->assertSame(
            [],
            $this->hasher->getOptions()
        );
    }
}
