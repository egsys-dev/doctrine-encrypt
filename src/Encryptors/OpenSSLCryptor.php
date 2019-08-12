<?php

namespace DoctrineEncrypt\Encryptors;

use DoctrineEncrypt\Exception\HmacCalculationException;
use DoctrineEncrypt\Exception\InvalidCipherException;

/**
 * Class for OpenSSL encryption.
 *
 * @author Lucas Saraiva <lucassaraiva5@hotmail.com>
 */
class OpenSSLCryptor implements EncryptorInterface
{
    const CIPHER_AES_256_CBC = 'aes-256-cbc';
    const HMAC_SHA256 = 'sha256';

    private $privateKey;
    private $publicKey;
    private $iv;
    private $cipher;
    private $hmacHash;

    public function __construct(
        string $privateKey,
        string $publicKey,
        string $iv,
        string $cipher = self::CIPHER_AES_256_CBC,
        string $hmacHash = self::HMAC_SHA256
    ) {
        $method = array_flip(openssl_get_cipher_methods());

        if (!isset($method[$cipher])) {
            throw new InvalidCipherException('O algoritmo informado para a criptografia é inválido.');
        }

        $this->privateKey = $privateKey;
        $this->publicKey = $publicKey;
        $this->iv = $iv;
        $this->cipher = $cipher;
        $this->hmacHash = $hmacHash;
    }

    public function encrypt(string $data): ?string
    {
        $ciphertextRaw = openssl_encrypt($data, $this->cipher, $this->privateKey, OPENSSL_RAW_DATA, $this->iv);
        $hmac = hash_hmac($this->hmacHash, $ciphertextRaw, $this->publicKey, true);
        $encrypted = base64_encode($this->iv.$hmac.$ciphertextRaw);

        return $encrypted ? $encrypted : '';
    }

    public function decrypt(string $data): ?string
    {
        $decodedData = base64_decode($data);
        $ivlen = openssl_cipher_iv_length($this->cipher);
        $hmac = substr($decodedData, $ivlen, $sha2len = 32);
        $ciphertextRaw = substr($decodedData, $ivlen + $sha2len);

        $originalPlaintext = openssl_decrypt($ciphertextRaw, $this->cipher, $this->privateKey, OPENSSL_RAW_DATA, $this->iv);
        $calcmac = hash_hmac($this->hmacHash, $ciphertextRaw, $this->publicKey, true);

        if (!hash_equals($hmac, $calcmac)) {
            throw new HmacCalculationException('Não foi possivel descriptografar o valor informado');
        }

        return $originalPlaintext ? $originalPlaintext : '';
    }
}
