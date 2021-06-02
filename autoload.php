<?php
/**
 * Paragon Initiative Enterprises - Password Lock
 * PSR-4 compatible autoloader
 *
 * @psalm-suppress MissingClosureParamType
 */
\spl_autoload_register(function ($class) {
    // Project-specific namespace prefix
    $prefix = 'ParagonIE\\PasswordLock';

    // Base directory for the namespace prefix
    $base_dir = __DIR__.'/src/';

    // Does the class use the namespace prefix?
    $len = \strlen($prefix);
    if (\strncmp($prefix, $class, $len) !== 0) {
        // no, move to the next registered autoloader
        return;
    }

    // Get the relative class name
    $relative_class = \substr($class, $len);

    // Replace the namespace prefix with the base directory, replace namespace
    // separators with directory separators in the relative class name, append
    // with .php
    $file = $base_dir.
        \str_replace(
            ['\\', '_'],
            '/',
            $relative_class
        ).'.php';

    // If the file exists, require it
    if (\file_exists($file)) {
        require $file;
    }
});

if (file_exists(__DIR__ . '/vendor/autoload.php')) {
    /** @psalm-suppress MissingFile */
    include_once __DIR__ . '/vendor/autoload.php';
}
