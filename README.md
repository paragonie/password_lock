# Password Lock

**MIT Licensed** - feel free to use to enhance the security of any of your PHP projects

Wraps Bcrypt-SHA256 in Authenticated Encryption. Published by [Paragon Initiative Enteprises](https://paragonie.com).

Depends on [defuse/php-encryption](https://github.com/defuse/php-encryption) for authenticated symmetric-key encryption

## How is this different than "peppering"?

Peppering strategies are usually accomplished through a keyed hash function (e.g. HMAC-SHA256) and applies to the password before it's passed to the salted hash API (i.e. bcrypt). If your pepper/HMAC key is ever compromised, you have to reset every user's password and it becomes a headache.

A hash then encrypt strategy offers **agility**; if your secret key is compromised (but, miraculously, the hashes are not), you can decrypt all of your users' hashes then re-encrypt them with a new key and they'll never suffer the inconvenience of an unscheduled password reset.
