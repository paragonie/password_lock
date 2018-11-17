# Password Lock

**MIT Licensed** - feel free to use to enhance the security of any of your PHP projects

Wraps Password Hashing in Authenticated Encryption. Published by [Paragon Initiative Enteprises](https://paragonie.com). Check out our other [open source projects](https://paragonie.com/projects) too.

Depends on [defuse/php-encryption](https://github.com/defuse/php-encryption) for authenticated symmetric-key encryption.

## How is this different than "peppering"?

Peppering strategies are usually accomplished through a keyed hash function (e.g. HMAC-SHA256) and applies to the password before it's passed to the salted hash API (i.e. bcrypt). If your pepper/HMAC key is ever compromised, you have to reset every user's password and it becomes a headache.

A hash then encrypt strategy offers **agility**; if your secret key is compromised (but, miraculously, the hashes are not), you can decrypt all of your users' hashes then re-encrypt them with a new key and they'll never suffer the inconvenience of an unscheduled password reset.

## How much more secure is this than just using bcrypt?

* You don't have to worry about the 72 character limit for bcrypt
* You don't have to worry about accidentally creating a null-byte truncation vulnerability
* If your database gets hacked, and your database is on a separate machine from your webserver, the attacker has to first decrypt the hashes before attempting to crack any of them.

Here's a [proof-of-concept](http://3v4l.org/61VZq) for the first two points.

But realistically, this library is only about as a secure as bcrypt.

## Usage Examples

### Hash Password, Encrypt Hash, Authenticate Ciphertext

```php
<?php

use ParagonIE\PasswordLock\PasswordLock;
use Defuse\Crypto\Key;

$key = Key::createNewRandomKey();

$passwordLock = new PasswordLock($key);

if (isset($_POST['password'])) {
    if (!is_string($_POST['password'])) {
        die('Password must be a string');
    }
    
    $storeMe = $passwordLock->hashAndEncrypt($_POST['password']);
}
```
 
### Verify MAC, Decrypt Ciphertext, Verify Password

```php
<?php

...

if (isset($_POST['password'])) {
    if (!is_string($_POST['password'])) {
        die('Password must be a string');
    }
    
    if ($passwordLock->decryptAndVerify($_POST['password'], $storeMe)) {
        // Success!
    }
}
```

### Re-encrypt a hash with a different encryption key

```php
<?php

use ParagonIE\PasswordLock\PasswordLock;

$newKey = \Defuse\Crypto\Key::createNewRandomKey();
$newHash = PasswordLock::rotateKey($storeMe, $key, $newKey);
```

### Using Password hasher

by default, PasswordLock uses Bcrypt-SHA384 based PasswordHasher.

```php
<?php

use ParagonIE\PasswordLock\{
    PasswordLock,
    Hasher\PasswordHasher
};

// doing this : 
$hasher = new PasswordHasher(PASSWORD_DEFAULT, []);
$lock = new PasswordLock($key,$hasher);
// is same as this : 
$lock = new PasswordLock($key);
```

you can add options or specify another PHP `password_hash` algorithm as following :

```php
<?php

use ParagonIE\PasswordLock\{
    PasswordLock,
    Hasher\PasswordHasher
};

// use Argon2I algorithm instead of Bcrypt
$hasher = new PasswordHasher(PASSWORD_ARGON2I, [
    'memory_cost' => 2048
]);
$lock = new PasswordLock($key,$hasher);
```

## Costume Password Hasher

`ParagonIE\PasswordLock\PasswordLock` accepts any `ParagonIE\PasswordLock\Hasher\PasswordHasherInterface` implementation as the first argument.

```php
<?php

use ParagonIE\PasswordLock\{
    PasswordLock,
    Hasher\PasswordHasherInterface
};

class MyPasswordHasher implements PasswordHasherInterface 
{
    public function hash(string $password) : string
    {
        // hash password
    }
    
    public function verify(string $password, string $hash) : bool
    {
        // verify hash against the given password
    }
}

$hasher = new MyPasswordHasher();
$lock = new PasswordLock($key,$hasher);
```
