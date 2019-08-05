<?php

use DoctrineEncrypt\Encryptors\OpenSSLCryptor;
use DoctrineEncrypt\Encryptors\OpenSslEncryptor;

require __DIR__ . '/../vendor/autoload.php';

$cryptor = new OpenSSLCryptor('tempkey', 'tempkey.pub', "1234567890123456");
$crypted = $cryptor->encrypt("teste");