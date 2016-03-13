# Password Lock

**MIT Licensed** - feel free to use to enhance the security of any of your PHP projects

Wraps Bcrypt-SHA384 in Authenticated Encryption. Published by [Paragon Initiative Enteprises](https://paragonie.com). Check out our other [open source projects](https://paragonie.com/projects) too.

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
use \ParagonIE\PasswordLock\PasswordLock;
use \Defuse\Crypto\Key;

$newKey = Key::createNewRandomKey();
if (isset($_POST['password'])) {
    if (!is_string($_POST['password'])) {
        die("Password must be a string");
    }
    $storeMe = PasswordLock::hashAndEncrypt($_POST['password'], $key);
}
```
 
### Verify MAC, Decrypt Ciphertext, Verify Password

```php
if (isset($_POST['password'])) {
    if (!is_string($_POST['password'])) {
        die("Password must be a string");
    }
    if (PasswordLock::decryptAndVerify($_POST['password'], $storeMe, $key)) {
        // Success!
    }
}
```

### Re-encrypt a hash with a different encryption key

```php
$newKey = \Defuse\Crypto\Key::createNewRandomKey();
$newHash = PasswordLock::rotateKey($storeMe, $key, $newKey);
```

### Migrate from Version 1 of the library

```php
$newHash = PasswordLock::upgradeFromVersion1(
    $_POST['password'],
    $oldHash,
    $oldKey,
    $newKey
);
```