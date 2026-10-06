<?php

declare(strict_types=1);

namespace Marko\AuthenticationToken\Exceptions;

class InvalidTokenException extends TokenException
{
    /**
     * Takes no token value on purpose: exception context ends up in logs and
     * error pages.
     */
    public static function forToken(): self
    {
        return new self(
            message: 'Invalid token format',
            context: 'The presented token has an invalid or malformed format',
            suggestion: 'Ensure the token is a valid personal access token',
        );
    }
}
