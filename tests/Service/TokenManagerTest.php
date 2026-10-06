<?php

declare(strict_types=1);

namespace Marko\AuthenticationToken\Tests\Service;

use DateTimeImmutable;
use Marko\AuthenticationToken\Contracts\NewAccessToken;
use Marko\AuthenticationToken\Contracts\TokenRepositoryInterface;
use Marko\AuthenticationToken\Entity\PersonalAccessToken;
use Marko\AuthenticationToken\Event\AllTokensRevokedEvent;
use Marko\AuthenticationToken\Event\TokenCreatedEvent;
use Marko\AuthenticationToken\Event\TokenRevokedEvent;
use Marko\AuthenticationToken\Service\TokenManager;
use Marko\Testing\Fake\FakeAuthenticatable;
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

it('creates a new personal access token with SHA-256 hashed storage', function (): void {
    $repository = new FakeTokenRepository();
    $manager = new TokenManager($repository);
    $user = new FakeAuthenticatable(id: 1);

    $result = $manager->createToken($user, 'My Token');

    expect($repository->created)->toHaveCount(1)
        ->and($repository->created[0]->tokenHash)->toBe(hash('sha256', $result->plainTextToken));
});

it('returns NewAccessToken value object with plain-text token at creation time', function (): void {
    $repository = new FakeTokenRepository();
    $manager = new TokenManager($repository);
    $user = new FakeAuthenticatable(id: 1);

    $result = $manager->createToken($user, 'Test Token');

    expect($result)->toBeInstanceOf(NewAccessToken::class)
        ->and($result->plainTextToken)->not->toBeEmpty()
        ->and(strlen($result->plainTextToken))->toBe(80);
});

it('assigns abilities array to created token', function (): void {
    $repository = new FakeTokenRepository();
    $manager = new TokenManager($repository);
    $user = new FakeAuthenticatable(id: 1);

    $manager->createToken($user, 'Admin Token', ['read', 'write', 'delete']);

    expect($repository->created)->toHaveCount(1)
        ->and($repository->created[0]->abilities)->toBe(json_encode(['read', 'write', 'delete']));
});

it('revokes a token by its id', function (): void {
    $repository = new FakeTokenRepository();
    $manager = new TokenManager($repository);

    $manager->revokeToken(42);

    expect($repository->revoked)->toHaveCount(1)
        ->and($repository->revoked[0])->toBe(42);
});

it('revokes all tokens for a user', function (): void {
    $repository = new FakeTokenRepository();
    $manager = new TokenManager($repository);
    $user = new FakeAuthenticatable(id: 7);

    $manager->revokeAllTokens($user);

    expect($repository->revokedForUser)->toHaveKey(FakeAuthenticatable::class)
        ->and($repository->revokedForUser[FakeAuthenticatable::class])->toContain(7);
});

it('stores the provided expiresAt on the created personal access token', function (): void {
    $repository = new FakeTokenRepository();
    $manager = new TokenManager($repository);
    $user = new FakeAuthenticatable(id: 1);
    $expiresAt = new DateTimeImmutable('+1 hour');

    $manager->createToken($user, 'Expiring Token', expiresAt: $expiresAt);

    expect($repository->created)->toHaveCount(1)
        ->and($repository->created[0]->expiresAt)->toBe($expiresAt->format('Y-m-d H:i:s'));
});

it('leaves expiresAt null when no expiry is provided to createToken', function (): void {
    $repository = new FakeTokenRepository();
    $manager = new TokenManager($repository);
    $user = new FakeAuthenticatable(id: 1);

    $manager->createToken($user, 'Permanent Token');

    expect($repository->created)->toHaveCount(1)
        ->and($repository->created[0]->expiresAt)->toBeNull();
});

describe('token lifecycle events', function (): void {
    it(
        'dispatches TokenCreatedEvent with the user, name, abilities and expiry when a token is created',
        function (): void {
            $events = new FakeEventDispatcher();
            $manager = new TokenManager(new FakeTokenRepository(), $events);
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

    it('never includes the plain-text token in TokenCreatedEvent', function (): void {
        $events = new FakeEventDispatcher();
        $manager = new TokenManager(new FakeTokenRepository(), $events);

        $newToken = $manager->createToken(new FakeAuthenticatable(id: 3), 'ci');
        $event = $events->dispatched(TokenCreatedEvent::class)[0];

        expect(print_r($event, true))->not->toContain($newToken->plainTextToken)
            ->and(print_r($event, true))->not->toContain(hash('sha256', $newToken->plainTextToken));
    });

    it('dispatches TokenRevokedEvent with the token id when a token is revoked', function (): void {
        $events = new FakeEventDispatcher();
        $manager = new TokenManager(new FakeTokenRepository(), $events);

        $manager->revokeToken(42);

        $dispatched = $events->dispatched(TokenRevokedEvent::class);

        expect($dispatched)->toHaveCount(1)
            ->and($dispatched[0]->tokenId)->toBe(42);
    });

    it('dispatches AllTokensRevokedEvent with the user when all tokens are revoked', function (): void {
        $events = new FakeEventDispatcher();
        $manager = new TokenManager(new FakeTokenRepository(), $events);
        $user = new FakeAuthenticatable(id: 9);

        $manager->revokeAllTokens($user);

        $dispatched = $events->dispatched(AllTokensRevokedEvent::class);

        expect($dispatched)->toHaveCount(1)
            ->and($dispatched[0]->user)->toBe($user);
    });
});
