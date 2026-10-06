<?php

declare(strict_types=1);

namespace Marko\AuthenticationToken\Event;

use Marko\Core\Event\Event;

/**
 * Dispatched by TokenManager::revokeToken() after a token is revoked.
 */
class TokenRevokedEvent extends Event
{
    public function __construct(
        public readonly int $tokenId,
    ) {}
}
