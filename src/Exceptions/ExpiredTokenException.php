<?php

declare(strict_types=1);

namespace Marko\AuthenticationToken\Exceptions;

use DateTimeInterface;

class ExpiredTokenException extends TokenException
{
    /**
     * Never pass the token value: exception context ends up in logs and
     * error pages.
     */
    public static function forToken(
        ?int $tokenId,
        DateTimeInterface $expiredAt,
    ): self {
        $expiredAtFormatted = $expiredAt->format('Y-m-d H:i:s');
        $token = $tokenId !== null ? "Token #$tokenId" : 'The token';

        return new self(
            message: 'Token has expired',
            context: "$token expired at $expiredAtFormatted",
            suggestion: 'Please generate a new personal access token',
        );
    }
}
