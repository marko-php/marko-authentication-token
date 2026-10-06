<?php

declare(strict_types=1);

namespace Marko\AuthenticationToken\Exceptions;

use Marko\Authentication\Exceptions\AuthException;

/**
 * Thrown when a stateful guard method (attempt, login, loginById, logout) is
 * called on the token guard, which authenticates each request from its
 * bearer token and keeps no login state.
 */
class StatelessGuardException extends AuthException
{
    public static function forMethod(
        string $guard,
        string $method,
    ): self {
        return new self(
            message: "Cannot call $method() on token guard '$guard': token guards are stateless",
            context: 'The token guard authenticates each request from its Authorization: Bearer header and keeps no login state between requests',
            suggestion: 'Issue a token with TokenManager::createToken() and send it as "Authorization: Bearer <token>"; end access with TokenManager::revokeToken() or revokeAllTokens(). Use a session guard for login/logout flows',
        );
    }
}
