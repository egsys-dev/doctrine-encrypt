<?php

namespace DoctrineEncrypt\Encryptors;

/**
 * Encryptor interface for encryptors.
 *
 * @author Victor Melnik <melnikvictorl@gmail.com>
 */
interface EncryptorInterface
{
    /**
     * Must accept data and return encrypted data.
     *
     * @param string $data
     *
     * @return string
     */
    public function encrypt(string $data): ?string;

    /**
     * Must accept data and return decrypted data.
     *
     * @param string $data
     *
     * @return string
     */
    public function decrypt(string $data): ?string;
}
