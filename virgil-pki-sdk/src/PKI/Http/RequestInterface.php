<?php

namespace Virgil\PKI\Http;

interface RequestInterface {

    /**
     * @return string
     */
    public function getEndpoint();

    /**
     * @return string
     */
    public function getRequestMethod();

    /**
     * @return array
     */
    public function getHeaders();

    /**
     * @return string json
     */
    public function getBody();

    /**
     * @return bool
     */
    public function isBodyEmpty();

}