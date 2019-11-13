<?php
/**
 * Copyright (C) 2015-2018 Virgil Security Inc.
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     (1) Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *     (2) Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *
 *     (3) Neither the name of the copyright holder nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 */

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
