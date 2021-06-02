# Version 3.1.0 (2021-06-02)

* Added `needsRehash()` method.
* Added support for `$hashOptions` in `hashAndEncrypt()` to support
  custom bcrypt costs. (This can also be used to support custom Argon2id
  parameters, should the default ever change in PHP.)
* **Drops support for PHP 7.2 and older.**  
  Use v3.0.3 if you need older PHP support.

# Version 3.0.3 (2021-06-02)

* Support PHP 8.
* The previous tag (v3.0.2) was erroneous and erased.

# Version 3.0.1 (2016-05-20)

* Fixed `autoload.php`

# Version 3.0.0 (2016-05-18)

* Set minimum PHP version to 7.0
* Use strict_types

# Version 2.0.0 (2016-05-18)

* Update `defuse/php-encryption` to `2.0.0`
* Use `paragonie/constant_time_encoding`

# Version 1.1.0

* Added `PasswordLock::rotateKey()` to decrypt and re-encrypt a ciphertext.
* Better test coverage.

# Version 1.0.1

* Fixed `composer.json`.

# Version 1.0.0

* Initial release.
