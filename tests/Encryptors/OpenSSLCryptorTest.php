<?php
namespace DoctrineEncrypt\Tests\Encryptors;

use DoctrineEncrypt\Encryptors\OpenSSLCryptor;
use PHPUnit\Framework\TestCase;

class OpenSSLCryptorTest extends TestCase
{
    private $publicKey;
    private $privateKey;
    private $iv;

    public function setUp(): void
    {
        $this->publicKey = "foo";
        $this->privateKey = "bar";
        $this->iv = "dTN6Lid8NjVESTdYLVwtVw==";
    }

    public function testEncryptReturnsDecryptableValueWithSameIv()
    {
        $cryptor = new OpenSSLCryptor($this->privateKey, $this->publicKey, $this->iv);
        $cipherText = $cryptor->encrypt('test-data');

        $this->assertNotEquals('test-data', $cipherText);
        $this->assertEquals('test-data', $cryptor->decrypt($cipherText));
    }
}
