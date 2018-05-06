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

namespace Virgil\CryptoImpl\Cryptography\Core\Cipher;


use Virgil\CryptoImpl\Cryptography\Core\Crypto\VirgilDataSource;

/**
 * Class is representation of data provider stream.
 */
class VirgilStreamDataSource extends VirgilDataSource
{
    /** @var resource $stream */
    private $stream;

    /** @var int $dataChunk */
    private $dataChunk;


    /**
     * Class constructor.
     *
     * @param resource $stream
     * @param int      $dataChunk specifies length number of bytes read.
     */
    public function __construct($stream, $dataChunk = 1024)
    {
        parent::__construct($this);
        $this->stream = $stream;
        rewind($this->stream);
        $this->dataChunk = $dataChunk;
    }


    /**
     * Checks if there is data chunk.
     *
     * @return bool
     */
    public function hasData()
    {
        return !feof($this->stream);
    }


    /**
     * Read data chunk from stream.
     *
     * @return string
     */
    public function read()
    {
        return fread($this->stream, $this->dataChunk);
    }


    /**
     * Set pointer to begin of the stream.
     *
     * @return bool
     */
    public function reset()
    {
        return rewind($this->stream);
    }
}
