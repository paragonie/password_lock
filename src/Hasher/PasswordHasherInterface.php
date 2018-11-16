<?php

declare(strict_types=1);

namespace ParagonIE\PasswordLock\Hasher;

interface PasswordHasherInterface
{
    /**
     * @param string $password
     *
     * @return string
     */
    public function hash(string $password): string;

    /**
     * @param string $password
     * @param string $hash
     *
     * @return bool
     */
    public function verify(string $password, string $hash): bool;
}
