<?php

declare(strict_types=1);

namespace Marko\AuthenticationToken\Guard;

use Marko\Authentication\Contracts\UserProviderInterface;
use Marko\AuthenticationToken\Contracts\TokenRepositoryInterface;
use Marko\AuthenticationToken\Http\CurrentRequest;
use Marko\Core\Event\EventDispatcherInterface;
use Marko\Database\Config\DatabaseTimezoneConfig;
use Psr\Clock\ClockInterface;

/**
 * Builds the token guard for AuthManager. module.php registers it as the
 * `token` guard driver in GuardDriverRegistry.
 */
readonly class TokenGuardFactory
{
    public function __construct(
        private TokenRepositoryInterface $tokenRepository,
        private CurrentRequest $currentRequest,
        private ClockInterface $clock,
        private DatabaseTimezoneConfig $databaseTimezoneConfig,
        private EventDispatcherInterface $eventDispatcher,
    ) {}

    public function create(
        string $name,
        UserProviderInterface $provider,
    ): TokenGuard {
        return new TokenGuard(
            repository: $this->tokenRepository,
            currentRequest: $this->currentRequest,
            clock: $this->clock,
            databaseTimezoneConfig: $this->databaseTimezoneConfig,
            provider: $provider,
            name: $name,
            eventDispatcher: $this->eventDispatcher,
        );
    }
}
