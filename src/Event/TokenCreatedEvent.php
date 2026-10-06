<?php

declare(strict_types=1);

namespace Marko\AuthenticationToken\Event;

use DateTimeImmutable;
use Marko\Authentication\AuthenticatableInterface;
use Marko\Core\Event\Event;

/**
 * Dispatched by TokenManager::createToken() after a personal access token is
 * stored. Carries no token value, plain-text or hashed.
 */
class TokenCreatedEvent extends Event
{
    /**
     * @param array<string> $abilities
     */
    public function __construct(
        public readonly AuthenticatableInterface $user,
        public readonly ?int $tokenId,
        public readonly string $name,
        public readonly array $abilities,
        public readonly ?DateTimeImmutable $expiresAt,
    ) {}
}
