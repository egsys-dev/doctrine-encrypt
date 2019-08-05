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
    const CIPHER_ALGORITM = 'aes-256-cbc';
    const HMAC_ALGORITM = 'sha256';

    private $privateKey;
    private $publicKey;
    private $iv;

    public function __construct(string $privateKey, string $publicKey, string $iv)
    {
        $method = array_flip(openssl_get_cipher_methods());

        if (!isset($method[self::CIPHER_ALGORITM])) {
            throw new InvalidCipherException('O algoritmo informado para a criptografia é inválido.');
        }

        $this->privateKey = $privateKey;
        $this->publicKey = $publicKey;
        $this->iv = base64_decode($iv);
    }

    public function encrypt(string $data): string
    {
        $ciphertext_raw = openssl_encrypt($data, self::CIPHER_ALGORITM, $this->privateKey, OPENSSL_RAW_DATA, $this->iv);
        $hmac = hash_hmac(self::HMAC_ALGORITM, $ciphertext_raw, $this->publicKey, true);
        $encrypted = base64_encode($this->iv.$hmac.$ciphertext_raw);

        return $encrypted;
    }

    public function decrypt(string $data): string
    {
        $c = base64_decode($data);
        $ivlen = openssl_cipher_iv_length(self::CIPHER_ALGORITM);
        $hmac = substr($c, $ivlen, $sha2len = 32);
        $ciphertext_raw = substr($c, $ivlen + $sha2len);

        $original_plaintext = openssl_decrypt($ciphertext_raw, self::CIPHER_ALGORITM, $this->privateKey, OPENSSL_RAW_DATA, $this->iv);
        $calcmac = hash_hmac(self::HMAC_ALGORITM, $ciphertext_raw, $this->publicKey, true);

        if (!hash_equals($hmac, $calcmac)) {
            throw new HmacCalculationException('Não foi possivel descriptografar o valor informado');
        }

        return $original_plaintext;
    }
}
