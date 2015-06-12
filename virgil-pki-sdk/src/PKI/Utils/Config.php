<?php

namespace Virgil\PKI\Utils;

class Config {

    protected $_config = array();

    public function __construct($params = array()) {
        $this->_config = $params;
    }

    public function __get($name) {
        if(isset($this->_config[$name])) {
            return $this->_config[$name];
        }

        return null;
    }

    public function __set($name, $value) {
        $this->_config[$name] = $value;
    }

}