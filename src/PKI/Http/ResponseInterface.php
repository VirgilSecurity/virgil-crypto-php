<?php

namespace Virgil\PKI\Http;

interface ResponseInterface {

    const HTTP_CODE_OK                    = 200;
    const HTTP_CODE_BAD_REQUEST           = 400;
    const HTTP_CODE_UNAUTHORIZED          = 401;
    const HTTP_CODE_METHOD_NOT_ALLOWED    = 405;
    const HTTP_CODE_NOT_FOUND             = 404;
    const HTTP_CODE_INTERNAL_SERVER_ERROR = 500;

}