<?php

namespace Virgil\PKI\Clients;

use Virgil\PKI\Http\ConnectionInterface;
use Virgil\PKI\Http\Request;

class ApiClient {

    protected $_connection = null;

    public function __construct(ConnectionInterface $connection) {
        $this->_connection = $connection;
    }

    public function get($endpoint) {
        return $this->_connection->send(Request::get($endpoint));
    }

    public function post($endpoint, $data) {
        return $this->_connection->send(Request::post($endpoint, $data));
    }

    public function put($endpoint, $data) {
        return $this->_connection->send(Request::put($endpoint, $data));
    }

    public function delete($endpoint) {
        return $this->_connection->send(Request::delete($endpoint));
    }

}