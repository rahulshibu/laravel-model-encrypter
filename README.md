# Laravel Db Encrypter Package

This package was created to encrypt and decrypt values of Eloquent model attributes.

## Key features

* Encrypt, decrypt values stored in database fields
* Using standard Laravel's Crypt service
* Easy configuration

## Requirements

* Laravel: 6.0 and up
* PHP: 7.1 and newer

#### Database schema

Encrypted values are stored as plain text so in most cases takes up more spaces then unencrypted one.
Recommendation is to alter table column to `TEXT` type.
If you want use `VARCHAR` or `CHAR` column type still you need to check if encrypted value fit.

#### Note:
Do not worry if you have current data in your database not encrypted and added column to `$encryptable`  - they will return as is.    
On save values will be encrypted and everything will work fine.

## Installation

Via Composer command line:

```bash
$ composer require rahulshibu/laravel-model-encrypter
```

## Usage

1. Use the `LaravelModelEncrypter\Traits\DBEncryptor` trait in any Eloquent model that you wish to use encryption
2. Define a `protected $encryptable` array containing a list of the encrypted attributes.
3. Define the encryption key in .env file. Default encrption key will be empty.

For example:

Model
```php
    
    use LaravelModelEncrypter\Traits\DBEncryptor;

    class Client extends Eloquent {
        use DBEncryptor;
       
        /** @var array The attributes that should be encrypted/decrypted */
        protected $encryptable = [
            'id_number', 
            'email',
        ];
    }
```

ENV

```bash
ENCRYPT_KEY=abcd1234
```


3. You can use Laravel's original $casts to cast decrypted values

### License
The MIT License (MIT). Please see [License File](LICENSE.md) for more information.
