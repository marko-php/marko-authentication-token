<?php

declare(strict_types=1);

namespace Marko\AuthenticationToken\Event;

use Marko\Core\Event\Event;

/**
 * Dispatched by TokenGuard when a request presents a bearer token that is
 * unknown, revoked or expired. Dispatched at most once per request and guard.
 *
 * Carries no token value, so it is safe to log and to feed a rate limiter
 * keyed on the IP address. A request without a bearer token and a successful
 * authentication dispatch nothing.
 */
class TokenAuthenticationFailedEvent extends Event
{
    public function __construct(
        public readonly string $guard,
        public readonly TokenFailureReason $reason,
        public readonly ?int $tokenId = null,
        public readonly ?string $ipAddress = null,
    ) {}
}
