# DoctrineEncrypt
[![Build Status](https://travis-ci.org/nepda/doctrine-encrypt.svg?branch=master)](https://travis-ci.org/nepda/doctrine-encrypt)

Package encrypts and decrypts Doctrine fields through life cycle events. This version of the Doctrine Encrypt package
distinguishes itself with the following features:

- Superior Annotation parsing & caching using Doctrine's built in libraries for superior performance
- Totally transparent field encryption: the value will only be encrypted in the database, never in the value
- Unit testing

## Tests

Tests currently run with PHP 7.1, 7.2

## Installation
Execute follow command:
```
composer require lucascardoso-egsys/doctrine-encrypt
```


### Manually
Add the event subscriber to your entity manager's event manager. Assuming `$em` is your configured entity manager:

```php
<?php

//You should pick your own hexadecimal secret
$secret = ["public" => "publicKeyRsa2048Generated", "private" => "privateKeyRsa2048Generated"];

$subscriber = new DoctrineEncryptSubscriber(
    new \Doctrine\Common\Annotations\AnnotationReader,
    new \DoctrineEncrypt\Encryptors\OpenSslEncryptor($secret)
);

$eventManager = $em->getEventManager();
$eventManager->addEventSubscriber($encrypt_subscriber);
```

## Usage
```php
<?php

namespace Your\CoolNamespace;

use Doctrine\ORM\Mapping as ORM;

use DoctrineEncrypt\Configuration\Encrypted;

/**
 * @ORM\Entity
 */
class Entity
{
    /**
     * @ORM\Id
     * @ORM\GeneratedValue(strategy="AUTO")
     * @ORM\Column(type="integer")
     * @var int
     */
    protected $id;

    /**
     * @ORM\Column(type="text")
     * @Encrypted
     * @var string
     */
    protected $secret_data;
}
```

## License

This bundle is under the MIT license. See the complete license in the bundle
