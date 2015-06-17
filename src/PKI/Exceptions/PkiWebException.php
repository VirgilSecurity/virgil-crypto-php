<?php

namespace Virgil\PKI\Exceptions;

class PkiWebException extends \Exception {

    protected $_errorCode;
    protected $_httpStatusCode;
    protected $_content;

    public function __construct($errorCode, $errorMessage, $httpStatusCode, $content = null) {
        $this->_errorCode      = $errorCode;
        $this->_errorMessage   = $errorMessage;
        $this->_httpStatusCode = $httpStatusCode;
        $this->_content        = $content;

        parent::__construct($errorMessage);
    }

    public function getErrorCode() {
        return $this->_errorCode;
    }

    public function getHttpStatusCode() {
        return $this->_httpStatusCode;
    }

    public function getContent() {
        return $this->_content;
    }

}