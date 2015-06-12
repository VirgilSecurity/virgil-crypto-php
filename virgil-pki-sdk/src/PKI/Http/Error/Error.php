<?php

namespace Virgil\PKI\Http\Error;

use Virgil\PKI\Http\ResponseInterface;

class Error {

    protected static $_errorMap = array(
        '10000' => 'Internal application error',
        '10001' => 'Application kernel error',
        '10010' => 'Internal application error',
        '10011' => 'Internal application error',
        '10012' => 'Internal application error',
        '10100' => 'JSON specified as a request body is invalid',
        '10200' => 'Guid specified is expired already',
        '10201' => 'The Guid specified is invalid',
        '10202' => 'The Authorization header was not specified',
        '10203' => 'Certificate header not specified or incorrect',
        '10204' => 'The signed digest specified is incorrect',
        '20000' => 'Account object not found for id specified',
        '20100' => 'Certificate object not found for id specified',
        '20101' => 'Certificate\'s public key invalid',
        '20102' => 'Certificate\'s public key not specified',
        '20103' => 'Certificate\'s public key must be base64-encoded string',
        '20200' => 'Ticket object not found for id specified',
        '20201' => 'Ticket type specified is invalid',
        '20202' => 'Ticket type specified for user identity is invalid',
        '20203' => 'Domain specified for domain identity is invalid',
        '20204' => 'Email specified for email identity is invalid',
        '20205' => 'Phone specified for phone identity is invalid',
        '20206' => 'Fax specified for fax identity is invalid',
        '20207' => 'Application specified for application identity is invalid',
        '20208' => 'Mac address specified for mac address identity is invalid',
        '20210' => 'Ticket integrity constraint violation',
        '20211' => 'Ticket confirmation entity not found by code specified',
        '20212' => 'Ticket confirmation code invalid',
        '20213' => 'Ticket was already confirmed and does not need further confirmation',
        '20214' => 'Ticket class specified is invalid',
        '20300' => 'User info ticket validation failed. Name is invalid',
        '20400' => 'Sign digest parameter validation failed',
        '20401' => 'Sign hash parameter validation failed',
    );

    protected static $_httpErrorMap = array(
        ResponseInterface::HTTP_CODE_BAD_REQUEST  => 'Request error',
        ResponseInterface::HTTP_CODE_UNAUTHORIZED => 'Authorization error',
        ResponseInterface::HTTP_CODE_METHOD_NOT_ALLOWED => 'Method not allowed',
        ResponseInterface::HTTP_CODE_NOT_FOUND => 'Entity not found',
        ResponseInterface::HTTP_CODE_INTERNAL_SERVER_ERROR => 'Internal Server Error'
    );

    public static function getErrorMessage($errorCode, $default = null) {
        if(isset(self::$_errorMap[$errorCode])) {
            return self::$_errorMap[$errorCode];
        }

        return $default;
    }

    public static function getHttpErrorMessage($httpStatusCode, $errorCode = null, $default = null) {
        if(self::getErrorMessage($errorCode)) {
            return self::getErrorMessage($errorCode);
        }

        if(isset(self::$_httpErrorMap[$httpStatusCode])) {
            return self::$_httpErrorMap[$httpStatusCode];
        }

        return $default;
    }

}