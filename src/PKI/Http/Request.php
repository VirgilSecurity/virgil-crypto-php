<?php

namespace Virgil\PKI\Http;

class Request implements RequestInterface {

    protected $_method   = null;
    protected $_endpoint = null;
    protected $_data     = array();
    protected $_headers  = array();

    public function __construct($method, $endpoint, $data = array(), $headers = array()) {
        $this->_method   = $method;
        $this->_endpoint = $endpoint;
        $this->_data     = $data;
        $this->_headers  = $headers;
    }

    // to do call static
    public static function get($endpoint) {
        return new self('GET', $endpoint);
    }

    public static function post($endpoint, $data) {
        return new self('POST', $endpoint, $data);
    }

    public static function delete($endpoint) {
        return new self('DELETE', $endpoint);
    }

    public static function put($endpoint, $data) {
        return new self('PUT', $endpoint, $data);
    }

    public function addHeader($header, $value) {
        $this->_headers[$header] = $value;
    }

    /**
     * @return string
     */
    public function getEndpoint() {
        return $this->_endpoint;
    }

    /**
     * @return string
     */
    public function getRequestMethod() {
        return $this->_method;
    }

    /**
     * @return array
     */
    public function getHeaders() {
        return $this->_headers;
    }

    /**
     * @return array
     */
    public function getBody() {
        return $this->_data;
    }

    public function isBodyEmpty() {
        return empty($this->_data);
    }
}