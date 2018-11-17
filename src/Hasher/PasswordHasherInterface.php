<?php

declare(strict_types=1);

namespace ParagonIE\PasswordLock\Hasher;

interface PasswordHasherInterface
{
    public function hash(string $password): string;

    public function verify(string $password, string $hash): bool;
}
