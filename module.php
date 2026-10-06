<?php

declare(strict_types=1);

use Marko\Authentication\Contracts\GuardInterface;
use Marko\Authentication\Contracts\UserProviderInterface;
use Marko\Authentication\Guard\GuardDriverRegistry;
use Marko\AuthenticationToken\Guard\TokenGuardFactory;
use Marko\AuthenticationToken\Http\CurrentRequest;
use Marko\AuthenticationToken\Middleware\TokenRequestMiddleware;
use Marko\Core\Container\ContainerInterface;

return [
    // TokenRequestMiddleware must hand the request to the token guard before
    // AuthorizationMiddleware (#[Can]) checks it.
    'sequence' => [
        'before' => ['marko/authorization'],
    ],
    'bindings' => [
        // TokenRepositoryInterface::class => ConcreteTokenRepository::class,
    ],
    'singletons' => [
        CurrentRequest::class,
    ],
    'globalMiddleware' => [
        TokenRequestMiddleware::class,
    ],
    // Serve the 'token' guard driver. The factory is resolved when a token
    // guard is first built, so booting never needs a TokenRepositoryInterface.
    'boot' => function (GuardDriverRegistry $guardDriverRegistry, ContainerInterface $container): void {
        $guardDriverRegistry->extend(
            'token',
            fn (string $name, array $config, UserProviderInterface $provider): GuardInterface => $container
                ->get(TokenGuardFactory::class)
                ->create($name, $provider),
        );
    },
];
