<?php

declare(strict_types=1);

namespace Marko\AuthenticationToken\Tests\Service;

use DateTimeImmutable;
use Marko\AuthenticationToken\Config\TokenConfig;
use Marko\AuthenticationToken\Contracts\NewAccessToken;
use Marko\AuthenticationToken\Contracts\TokenRepositoryInterface;
use Marko\AuthenticationToken\Entity\PersonalAccessToken;
use Marko\AuthenticationToken\Event\AllTokensRevokedEvent;
use Marko\AuthenticationToken\Event\TokenCreatedEvent;
use Marko\AuthenticationToken\Event\TokenRevokedEvent;
use Marko\AuthenticationToken\Service\TokenManager;
use Marko\Config\ConfigRepository;
use Marko\Config\Exceptions\ConfigException;
use Marko\Testing\Fake\FakeAuthenticatable;
use Marko\Testing\Fake\FakeClock;
use Marko\Testing\Fake\FakeEventDispatcher;

class FakeTokenRepository implements TokenRepositoryInterface
{
    /** @var list<PersonalAccessToken> */
    public array $created = [];

    /** @var list<int> */
    public array $revoked = [];

    /** @var array<string, list<int|string>> */
    public array $revokedForUser = [];

    public function find(
        int $id,
    ): ?PersonalAccessToken {
        return null;
    }

    public function findByToken(
        string $tokenHash,
    ): ?PersonalAccessToken {
        return null;
    }

    public function create(
        PersonalAccessToken $token,
    ): PersonalAccessToken {
        $token->id = count($this->created) + 1;
        $this->created[] = $token;

        return $token;
    }

    public function revoke(
        int $id,
    ): void {
        $this->revoked[] = $id;
    }

    public function revokeAllForUser(
        string $type,
        int|string $id,
    ): void {
        $this->revokedForUser[$type][] = $id;
    }
}

function tokenManager(
    FakeTokenRepository $repository = new FakeTokenRepository(),
    ?FakeEventDispatcher $eventDispatcher = null,
    ?int $expirationDays = 365,
): TokenManager {
    return new TokenManager(
        repository: $repository,
        config: new TokenConfig(new ConfigRepository([
            'authentication-token' => ['token_expiration_days' => $expirationDays],
        ])),
        clock: new FakeClock('2026-03-01 09:30:00'),
        eventDispatcher: $eventDispatcher,
    );
}

it('creates a new personal access token with SHA-256 hashed storage', function (): void {
    $repository = new FakeTokenRepository();
    $manager = tokenManager($repository);
    $user = new FakeAuthenticatable(id: 1);

    $result = $manager->createToken($user, 'My Token');

    expect($repository->created)->toHaveCount(1)
        ->and($repository->created[0]->tokenHash)->toBe(hash('sha256', $result->plainTextToken));
});

it('returns NewAccessToken value object with plain-text token at creation time', function (): void {
    $manager = tokenManager();
    $user = new FakeAuthenticatable(id: 1);

    $result = $manager->createToken($user, 'Test Token');

    expect($result)->toBeInstanceOf(NewAccessToken::class)
        ->and($result->plainTextToken)->not->toBeEmpty()
        ->and(strlen($result->plainTextToken))->toBe(80);
});

it('assigns abilities array to created token', function (): void {
    $repository = new FakeTokenRepository();
    $manager = tokenManager($repository);
    $user = new FakeAuthenticatable(id: 1);

    $manager->createToken($user, 'Admin Token', ['read', 'write', 'delete']);

    expect($repository->created)->toHaveCount(1)
        ->and($repository->created[0]->abilities)->toBe(json_encode(['read', 'write', 'delete']));
});

it('revokes a token by its id', function (): void {
    $repository = new FakeTokenRepository();
    $manager = tokenManager($repository);

    $manager->revokeToken(42);

    expect($repository->revoked)->toHaveCount(1)
        ->and($repository->revoked[0])->toBe(42);
});

it('revokes all tokens for a user', function (): void {
    $repository = new FakeTokenRepository();
    $manager = tokenManager($repository);
    $user = new FakeAuthenticatable(id: 7);

    $manager->revokeAllTokens($user);

    expect($repository->revokedForUser)->toHaveKey(FakeAuthenticatable::class)
        ->and($repository->revokedForUser[FakeAuthenticatable::class])->toContain(7);
});

it('stores an expiry of now plus the configured days when no expiresAt is given', function (): void {
    $repository = new FakeTokenRepository();
    $manager = tokenManager($repository, expirationDays: 30);

    $manager->createToken(new FakeAuthenticatable(id: 1), 'Default Lifetime Token');

    expect($repository->created)->toHaveCount(1)
        ->and($repository->created[0]->expiresAt)->toBe('2026-03-31 09:30:00');
});

it('stores a null expiry when token_expiration_days is null', function (): void {
    $repository = new FakeTokenRepository();
    $manager = tokenManager($repository, expirationDays: null);

    $manager->createToken(new FakeAuthenticatable(id: 1), 'Permanent Token');

    expect($repository->created)->toHaveCount(1)
        ->and($repository->created[0]->expiresAt)->toBeNull();
});

it('stores the explicit expiresAt instead of the configured default', function (): void {
    $repository = new FakeTokenRepository();
    $manager = tokenManager($repository, expirationDays: 30);

    $manager->createToken(
        new FakeAuthenticatable(id: 1),
        'Short Token',
        expiresAt: new DateTimeImmutable('2026-03-01 10:30:00'),
    );

    expect($repository->created)->toHaveCount(1)
        ->and($repository->created[0]->expiresAt)->toBe('2026-03-01 10:30:00');
});

it('sets createdAt from the clock', function (): void {
    $repository = new FakeTokenRepository();
    $manager = tokenManager($repository);

    $manager->createToken(new FakeAuthenticatable(id: 1), 'Token');

    expect($repository->created)->toHaveCount(1)
        ->and($repository->created[0]->createdAt)->toBe('2026-03-01 09:30:00');
});

it('fails loudly on an invalid token_expiration_days even when an explicit expiresAt is given', function (): void {
    $repository = new FakeTokenRepository();
    $manager = tokenManager($repository, expirationDays: 0);

    expect(fn (): NewAccessToken => $manager->createToken(
        new FakeAuthenticatable(id: 1),
        'Token',
        expiresAt: new DateTimeImmutable('2026-03-01 10:30:00'),
    ))->toThrow(ConfigException::class)
        ->and($repository->created)->toBeEmpty();
});

describe('token lifecycle events', function (): void {
    it(
        'dispatches TokenCreatedEvent with the user, name, abilities and expiry when a token is created',
        function (): void {
            $events = new FakeEventDispatcher();
            $manager = tokenManager(eventDispatcher: $events);
            $user = new FakeAuthenticatable(id: 3);
            $expiresAt = new DateTimeImmutable('2030-01-02 03:04:05');

            $manager->createToken($user, 'ci', ['deploy'], $expiresAt);

            $dispatched = $events->dispatched(TokenCreatedEvent::class);
            $event = $dispatched[0];

            expect($dispatched)->toHaveCount(1)
                ->and($event)->toBeInstanceOf(TokenCreatedEvent::class)
                ->and($event->user)->toBe($user)
                ->and($event->tokenId)->toBe(1)
                ->and($event->name)->toBe('ci')
                ->and($event->abilities)->toBe(['deploy'])
                ->and($event->expiresAt?->format('Y-m-d H:i:s'))->toBe('2030-01-02 03:04:05');
        },
    );

    it('dispatches TokenCreatedEvent with the computed default expiry', function (): void {
        $events = new FakeEventDispatcher();
        $manager = tokenManager(eventDispatcher: $events, expirationDays: 30);

        $manager->createToken(new FakeAuthenticatable(id: 3), 'ci');

        $dispatched = $events->dispatched(TokenCreatedEvent::class);

        expect($dispatched)->toHaveCount(1)
            ->and($dispatched[0]->expiresAt?->format('Y-m-d H:i:s'))->toBe('2026-03-31 09:30:00');
    });

    it('never includes the plain-text token in TokenCreatedEvent', function (): void {
        $events = new FakeEventDispatcher();
        $manager = tokenManager(eventDispatcher: $events);

        $newToken = $manager->createToken(new FakeAuthenticatable(id: 3), 'ci');
        $event = $events->dispatched(TokenCreatedEvent::class)[0];

        expect(print_r($event, true))->not->toContain($newToken->plainTextToken)
            ->and(print_r($event, true))->not->toContain(hash('sha256', $newToken->plainTextToken));
    });

    it('dispatches TokenRevokedEvent with the token id when a token is revoked', function (): void {
        $events = new FakeEventDispatcher();
        $manager = tokenManager(eventDispatcher: $events);

        $manager->revokeToken(42);

        $dispatched = $events->dispatched(TokenRevokedEvent::class);

        expect($dispatched)->toHaveCount(1)
            ->and($dispatched[0]->tokenId)->toBe(42);
    });

    it('dispatches AllTokensRevokedEvent with the user when all tokens are revoked', function (): void {
        $events = new FakeEventDispatcher();
        $manager = tokenManager(eventDispatcher: $events);
        $user = new FakeAuthenticatable(id: 9);

        $manager->revokeAllTokens($user);

        $dispatched = $events->dispatched(AllTokensRevokedEvent::class);

        expect($dispatched)->toHaveCount(1)
            ->and($dispatched[0]->user)->toBe($user);
    });
});
