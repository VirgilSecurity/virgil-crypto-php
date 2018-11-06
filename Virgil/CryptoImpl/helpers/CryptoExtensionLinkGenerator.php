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

namespace Virgil\CryptoImpl\helpers;

use VirgilVersion;

/**
 * Class CryptoExtensionDownloader
 * @package Virgil\Helpers
 */
class CryptoExtensionLinkGenerator
{
    const VIRGIL_VERSION = '2.6.1';
    const VIRGIL_CDN_MAIN_URL = 'https://cdn.virgilsecurity.com/virgil-crypto/php/';

    /**
     * @return string
     * @throws \Exception
     */
    public function getFullLink()
    {
        if($this->getVirgilVersion() == self::VIRGIL_VERSION)
        {
            return (string) self::VIRGIL_CDN_MAIN_URL.$this->getArchiveName();
        }
        else {
            throw new \Exception("Crypto Library ver. !== ".self::VIRGIL_VERSION." (latest)");
        }
    }

    /**
     * @return string
     */
    public function getArchiveName()
    {
        return 'virgil-crypto-'.$this->getVirgilVersion().'-php-'.$this->getPHPVersion().'-'.$this->getFullOSName().'-x'.$this->getSystemArch().'.'.$this->getExtension();
    }

    /**
     * @return string
     */
    private function getOSName()
    {
        return (string) strtolower(substr(PHP_OS, 0 , 3));
    }

    /**
     * @return string
     */
    private function getFullOSName()
    {
        if($this->isWindows() == true)
            return "windows-6.3";

        if($this->getOSName() == "dar")
            return "darwin-18.0";

        return 'linux';
    }

    /**
     * @return string
     */
    private function getVirgilVersion()
    {
        return (string) VirgilVersion::asString();
    }

    /**
     * @return float
     */
    public function getPHPVersion()
    {
        return (float) phpversion();
    }

    /**
     * @return string
     */
    private function getSystemArch()
    {
        $arch = strlen(decbin(~0));

        if($arch == 64 && $this->isWindows())
            return (string) $arch;

        return (string) "86_$arch";
    }

    /**
     * @return bool
     */
    public function isWindows()
    {
        return $this->getOSName() == 'win';
    }

    /**
     * @return string
     */
    public function getExtension()
    {
        return (string) $this->isWindows() ? 'zip' : 'tgz';
    }
}