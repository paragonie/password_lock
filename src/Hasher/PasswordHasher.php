<?php

declare(strict_types=1);

namespace ParagonIE\PasswordLock\Hasher;

use ParagonIE\ConstantTime\Base64;
use ParagonIE\PasswordLock\Exception\HashingException;
use const PASSWORD_DEFAULT;
use function hash;
use function is_string;
use function password_hash;
use function password_verify;

class PasswordHasher implements PasswordHasherInterface
{
    /**
     * @var array
     */
    protected $options;

    /**
     * @var int
     */
    protected $algorithm;

    public function __construct(int $algorithm = PASSWORD_DEFAULT, array $options = [])
    {
        $this->algorithm = $algorithm;
        $this->options = $options;
    }

    public function hash(string $password): string
    {
        $hash = password_hash(
            Base64::encode(
                hash('sha384', $password, true)
            ),
            $this->getAlgorithm(),
            $this->getOptions()
        );

        if (!is_string($hash)) {
            throw new HashingException('Unknown hashing error.');
        }

        return $hash;
    }

    public function verify(string $password, string $hash): bool
    {
        return password_verify(
            Base64::encode(
                hash('sha384', $password, true)
            ),
            $hash
        );
    }

    public function getAlgorithm(): int
    {
        return $this->algorithm;
    }

    public function getOptions(): array
    {
        return $this->options;
    }
}
