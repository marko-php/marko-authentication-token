<?php

declare(strict_types=1);

namespace Marko\AuthenticationToken\Event;

use Marko\Authentication\AuthenticatableInterface;
use Marko\Core\Event\Event;

/**
 * Dispatched by TokenManager::revokeAllTokens() after every token of a user
 * is revoked.
 */
class AllTokensRevokedEvent extends Event
{
    public function __construct(
        public readonly AuthenticatableInterface $user,
    ) {}
}
