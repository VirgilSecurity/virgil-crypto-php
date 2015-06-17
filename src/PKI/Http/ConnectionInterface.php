<?php

namespace Virgil\PKI\Http;

interface ConnectionInterface {

    /**
     * @return string
     */
    public function getBaseUrl();

    /**
     * @return string
     */
    public function getAppToken();

    /**
     * @param RequestInterface $request
     * @return Response
     */
    public function send(RequestInterface $request);

    /**
     * @return string
     */
    public function getApiVersion();

}