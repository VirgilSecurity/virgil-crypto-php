<?php

namespace Virgil\Tests;


/**
 * Class provides data for compatibility tests.
 */
class CompatibilityDataProvider
{

    /** @var array $jsonData */
    private $jsonData;


    /**
     * Class constructor.
     *
     * @param $pathToJsonData
     */
    public function __construct($pathToJsonData)
    {
        $this->jsonData = json_decode(file_get_contents($pathToJsonData), true);
    }


    /**
     * Returns private key, original data and resulting signature in a set.
     *
     * @return array
     */
    public function getGenerateSignatureData()
    {
        return [$this->jsonData['generate_signature']];
    }


    /**
     * @return mixed
     */
    public function getDecryptThenVerifyMultipleSigners()
    {
        return [$this->jsonData['sign_then_encrypt_multiple_signers']];
    }


    /**
     * Returns private key, encrypted data and initial original data in a set.
     *
     * @return array
     */
    public function getEncryptArgumentsSetWithOriginalContent()
    {
        return array_merge(
            [$this->getEncryptSingleRecipientData()],
            $this->makeSingleRecipientsFromMultiple($this->getEncryptMultipleRecipients())
        );
    }


    /**
     * Returns private key, signer private key, encrypted data and initial original data in a set.
     *
     * @return array
     */
    public function getSignThenEncryptRecipientsData()
    {
        $data = array_merge(
            [$this->getSignThenEncryptSingleRecipientData()],
            $this->makeSingleRecipientsFromMultiple($this->getSignThenEncryptMultipleRecipients())
        );
        $i = 0;
        foreach ($data as &$item) {
            if ($i < 2) {
                $item['signer_private_key'] = $item['private_key'];
            } else {
                $item['signer_private_key'] = $data[1]['signer_private_key'];
            }
            $i++;
        }

        return $data;
    }


    private function makeSingleRecipientsFromMultiple($multipleRecipients)
    {
        $data = [];
        foreach ($multipleRecipients['private_keys'] as $private_key) {
            $data[] = [
                'private_key'   => $private_key,
                'original_data' => $multipleRecipients['original_data'],
                'cipher_data'   => $multipleRecipients['cipher_data'],
            ];
        }

        return $data;
    }


    private function getEncryptSingleRecipientData()
    {
        return $this->jsonData['encrypt_single_recipient'];
    }


    private function getEncryptMultipleRecipients()
    {
        return $this->jsonData['encrypt_multiple_recipients'];
    }


    private function getSignThenEncryptMultipleRecipients()
    {
        return $this->jsonData['sign_then_encrypt_multiple_recipients'];
    }


    private function getSignThenEncryptSingleRecipientData()
    {
        return $this->jsonData['sign_then_encrypt_single_recipient'];
    }
}
