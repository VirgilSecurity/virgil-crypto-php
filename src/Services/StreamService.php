<?php
/**
 * Copyright (C) 2015-2019 Virgil Security Inc.
 * All rights reserved.
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *     (1) Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *     (2) Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *     (3) Neither the name of the copyright holder nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
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
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 */

namespace Virgil\CryptoImpl\Services;

use Virgil\CryptoImpl\Core\OutputStream;
use Virgil\CryptoImpl\Core\StreamInterface;
use Virgil\CryptoImpl\Core\VirgilCryptoError;
use Virgil\CryptoImpl\Exceptions\VirgilCryptoServiceException;

/**
 * Class StreamUtils
 *
 * @package Virgil\CryptoImpl\Services
 */
class StreamService
{
    /**
     * @param string $data
     * @param OutputStream $outputStream
     *
     * @throws VirgilCryptoServiceException
     */
    public static function write(string $data, OutputStream $outputStream)
    {
        $handle = fopen($outputStream->getOutput(), "a");
        if (!$handle)
            throw new VirgilCryptoServiceException(VirgilCryptoError::OUTPUT_STREAM_ERROR());

        fwrite($handle, $data);
        fclose($handle);
    }

    /**
     * @param StreamInterface $stream
     * @param int|null $streamSize
     * @param callable $chunkClosure
     * @param bool $withReturn
     *
     * @throws VirgilCryptoServiceException
     */
    public static function forEachChunk(StreamInterface $stream, int $streamSize = null, callable $chunkClosure, bool
    $withReturn = true)
    {
        $handle = fopen($stream->getInputStream()->getInput(), "rb");
        if (!$handle) {
            throw new VirgilCryptoServiceException(VirgilCryptoError::INPUT_STREAM_ERROR());
        }

        while (!feof($handle)) {
            if (!$streamSize)
                $streamSize = filesize($stream->getInputStream()->getInput());

            $content = fread($handle, $streamSize);

            if($withReturn) {
                $data = $chunkClosure($content);
                self::write($data, $stream->getOutputStream());
            } else {
                $chunkClosure($content);
            }
        }
    }
}