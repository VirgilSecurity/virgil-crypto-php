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

#namespace Virgil\CryptoImpl\Cryptography\Cipher;


use VirgilDataSink;

/**
 * Class is representation of data consumer stream.
 */
class VirgilStreamDataSink extends VirgilDataSink
{
    /** @var resource $stream */
    private $stream;


    /**
     * Class constructor.
     *
     * @param resource $stream
     */
    public function __construct($stream)
    {
        parent::__construct($this);
        $this->stream = $stream;
    }


    /**
     * Checks if sink stream is good for write.
     *
     * @return bool
     */
    function isGood()
    {
        $meta = stream_get_meta_data($this->stream);
        $mode = $meta['mode'];

        return false === strpos($mode, 'r') || true === strpos($mode, 'r+');
    }


    /**
     * Write chunk of encrypted data to sink stream.
     *
     * @param string $data
     *
     * @return int
     */
    function write($data)
    {
        return fwrite($this->stream, $data);
    }
}
