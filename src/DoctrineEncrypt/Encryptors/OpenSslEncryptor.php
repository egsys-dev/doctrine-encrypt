<?php

namespace DoctrineEncrypt\Encryptors;

use Symfony\Component\HttpFoundation\Response;

/**
 * Class for OpenSSL encryption.
 *
 * @author Lucas Saraiva <lucassaraiva5@hotmail.com>
 */
class OpenSslEncryptor implements EncryptorInterface
{
    const CIPHER_ALGORITM = 'aes-256-cbc';

    const HMAC_ALGORITM = 'sha256';

    private $privateKey;

    private $publicKey;

    private $passPhrase;

    private $iv;

    /**
     * Initialization of encryptor.
     *
     * @param string $privateKey
     * @param string $publicKey
     * @param string $passPhrase
     * @param string $ivBase64
     */
    public function __construct(string $privateKey, string $publicKey, string $passPhrase, string $ivBase64)
    {
        $this->privateKey = $privateKey;
        $this->publicKey = $publicKey;
        $this->passPhrase = $passPhrase;
        $this->iv = base64_decode($ivBase64);

        $pub_id = openssl_get_publickey($this->publicKey);
        $this->key_len = openssl_pkey_get_details($pub_id)['bits'];

        $method = array_flip(openssl_get_cipher_methods());

        if (!isset($method[self::CIPHER_ALGORITM])) {
            throw new \Exception('O algoritmo informado para a criptografia é inválido.', Response::HTTP_INTERNAL_SERVER_ERROR);
        }
    }

    public function encrypt(string $data): string
    {
        //$privateKey = openssl_get_privatekey($this->privateKey, $this->passPhrase);

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

        //$privateKey = openssl_get_privatekey($this->privateKey,$this->passPhrase);
        $original_plaintext = openssl_decrypt($ciphertext_raw, self::CIPHER_ALGORITM, $this->privateKey, OPENSSL_RAW_DATA, $this->iv);
        $calcmac = hash_hmac(self::HMAC_ALGORITM, $ciphertext_raw, $this->publicKey, true);

        if (!hash_equals($hmac, $calcmac)) {
            throw new \Exception('Não foi possivel descriptografar o valor informado', Response::HTTP_INTERNAL_SERVER_ERROR);
        }

        return $original_plaintext;
    }
}
