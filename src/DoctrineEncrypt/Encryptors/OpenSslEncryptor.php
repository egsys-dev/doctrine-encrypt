<?php

namespace DoctrineEncrypt\Encryptors;

/**
 * Class for OpenSSL encryption
 *
 * @author Lucas Saraiva <lucassaraiva5@hotmail.com>
 */
class OpenSslEncryptor implements EncryptorInterface
{
    const RSA_ALGORITHM_KEY_TYPE = OPENSSL_KEYTYPE_RSA;
    const RSA_ALGORITHM_SIGN = OPENSSL_ALGO_SHA256;
    const MAX_PART_LENGHT = 11;
    const MIN_PART_LENGHT = 8;

    private $privateKey;

    private $publicKey;

    private $passPhrase;

    /**
     * Initialization of encryptor
     * @param string $privateKey
     * @param string $publicKey
     * @param string $passPhrase
     */
    public function __construct(string $privateKey, string $publicKey, string $passPhrase)
    {
        $this->privateKey = $privateKey;
        $this->publicKey = $publicKey;
        $this->passPhrase = $passPhrase;

        $pub_id = openssl_get_publickey($this->publicKey);
        $this->key_len = openssl_pkey_get_details($pub_id)['bits'];
    }

    public function encrypt(string $data): string
    {
        $encrypted = '';
        $part_len = $this->key_len / self::MIN_PART_LENGHT - self::MAX_PART_LENGHT;
        $parts = str_split($data, $part_len);

        foreach ($parts as $part) {
            $encrypted_temp = '';
            openssl_public_encrypt($part, $encrypted_temp, $this->publicKey);
            $encrypted .= $encrypted_temp;
        }

        return base64_encode($encrypted);
    }

    public function decrypt(string $encrypted): string
    {
        $decrypted = "";
        $part_len = $this->key_len / self::MIN_PART_LENGHT;
        $base64_decoded = base64_decode($encrypted);
        $parts = str_split($base64_decoded, $part_len);
        $privateKey = openssl_get_privatekey($this->privateKey,$this->passPhrase);

        foreach ($parts as $part) {
            $decrypted_temp = '';
            openssl_private_decrypt($part, $decrypted_temp, $privateKey);
            $decrypted .= $decrypted_temp;
        }

        return $decrypted;
    }
}
