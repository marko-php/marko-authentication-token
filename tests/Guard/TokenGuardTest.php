<?php

declare(strict_types=1);

namespace Marko\AuthenticationToken\Tests\Guard;

use Marko\Authentication\AuthenticatableInterface;
use Marko\Authentication\Contracts\GuardInterface;
use Marko\Authentication\Contracts\StatelessGuardInterface;
use Marko\Authentication\Contracts\UserProviderInterface;
use Marko\Authentication\Exceptions\AuthException;
use Marko\AuthenticationToken\Contracts\TokenRepositoryInterface;
use Marko\AuthenticationToken\Entity\PersonalAccessToken;
use Marko\AuthenticationToken\Event\TokenAuthenticationFailedEvent;
use Marko\AuthenticationToken\Event\TokenFailureReason;
use Marko\AuthenticationToken\Exceptions\StatelessGuardException;
use Marko\AuthenticationToken\Guard\TokenGuard;
use Marko\AuthenticationToken\Http\CurrentRequest;
use Marko\Routing\Http\Request;
use Marko\Testing\Fake\FakeAuthenticatable;
use Marko\Testing\Fake\FakeClock;
use Marko\Testing\Fake\FakeEventDispatcher;
use Marko\Testing\Fake\FakeUserProvider;

function makeRequest(
    string $authHeader = '',
): Request {
    $server = ['REMOTE_ADDR' => '203.0.113.9'];

    if ($authHeader !== '') {
        $server['HTTP_AUTHORIZATION'] = $authHeader;
    }

    return new Request(server: $server);
}

function makeCurrentRequest(
    string $authHeader = '',
): CurrentRequest {
    $currentRequest = new CurrentRequest();
    $currentRequest->set(makeRequest($authHeader));

    return $currentRequest;
}

function makeRepository(
    ?PersonalAccessToken $token = null,
): TokenRepositoryInterface {
    return new readonly class ($token) implements TokenRepositoryInterface
    {
        public function __construct(
            private ?PersonalAccessToken $token,
        ) {}

        public function find(
            int $id,
        ): ?PersonalAccessToken {
            return null;
        }

        public function findByToken(
            string $tokenHash,
        ): ?PersonalAccessToken {
            return $this->token;
        }

        public function create(
            PersonalAccessToken $token,
        ): PersonalAccessToken {
            return $token;
        }

        public function revoke(
            int $id,
        ): void {}

        public function revokeAllForUser(
            string $type,
            int|string $id,
        ): void {}
    };
}

function makeUserProvider(
    ?AuthenticatableInterface $user = null,
): UserProviderInterface {
    return new FakeUserProvider($user !== null ? [$user->getAuthIdentifier() => $user] : []);
}

function makeToken(
    ?string $expiresAt = null,
    ?string $abilities = null,
): PersonalAccessToken {
    $token = new PersonalAccessToken();
    $token->id = 5;
    $token->tokenableId = 1;
    $token->tokenableType = FakeAuthenticatable::class;
    $token->expiresAt = $expiresAt;
    $token->abilities = $abilities;

    return $token;
}

function makeGuard(
    TokenRepositoryInterface $repository,
    CurrentRequest $currentRequest,
    ?AuthenticatableInterface $user = null,
    string $now = '2026-01-01 12:00:00',
    ?FakeEventDispatcher $eventDispatcher = null,
    string $name = 'token',
): TokenGuard {
    return new TokenGuard(
        repository: $repository,
        currentRequest: $currentRequest,
        clock: new FakeClock($now),
        provider: makeUserProvider($user),
        name: $name,
        eventDispatcher: $eventDispatcher,
    );
}

it('implements GuardInterface from marko/authentication', function (): void {
    expect(class_exists(TokenGuard::class))->toBeTrue()
        ->and(in_array(GuardInterface::class, class_implements(TokenGuard::class), true))->toBeTrue();
});

it('implements StatelessGuardInterface with a Bearer challenge', function (): void {
    $guard = makeGuard(makeRepository(), makeCurrentRequest());

    expect($guard)->toBeInstanceOf(StatelessGuardInterface::class)
        ->and($guard->getChallenge())->toBe('Bearer');
});

it('reports the configured guard name', function (): void {
    expect(makeGuard(makeRepository(), makeCurrentRequest(), name: 'api')->getName())->toBe('api');
});

it('extracts Bearer token from Authorization header', function (): void {
    $guard = makeGuard(makeRepository(), makeCurrentRequest('Bearer my-secret-token'));

    expect($guard->extractToken())->toBe('my-secret-token');
});

it('returns null user when no Authorization header is present', function (): void {
    $guard = makeGuard(makeRepository(), makeCurrentRequest());

    expect($guard->user())->toBeNull();
});

it('returns null user when token is not found or revoked', function (): void {
    $guard = makeGuard(makeRepository(), makeCurrentRequest('Bearer some-revoked-token'));

    expect($guard->user())->toBeNull();
});

it('treats a missing current request as a guest without dispatching an event', function (): void {
    $events = new FakeEventDispatcher();
    $guard = makeGuard(makeRepository(makeToken()), new CurrentRequest(), new FakeAuthenticatable(id: 1), eventDispatcher: $events);

    expect($guard->user())->toBeNull()
        ->and($guard->extractToken())->toBeNull()
        ->and($events->dispatched)->toBeEmpty();
});

it('checks token abilities for fine-grained authorization', function (): void {
    $guard = makeGuard(
        makeRepository(makeToken(abilities: json_encode(['read', 'write']))),
        makeCurrentRequest('Bearer valid-token'),
        new FakeAuthenticatable(id: 1),
    );

    expect($guard->hasAbility('read'))->toBeTrue()
        ->and($guard->hasAbility('write'))->toBeTrue()
        ->and($guard->hasAbility('delete'))->toBeFalse();
});

it('authenticates user by hashing token and looking up in repository', function (): void {
    $user = new FakeAuthenticatable(id: 1);
    $guard = makeGuard(makeRepository(makeToken()), makeCurrentRequest('Bearer plain-text-token'), $user);

    expect($guard->user())->toBe($user)
        ->and($guard->id())->toBe(1)
        ->and($guard->check())->toBeTrue()
        ->and($guard->guest())->toBeFalse();
});

it('resolves the user for a token whose expiresAt is null', function (): void {
    $user = new FakeAuthenticatable(id: 1);
    $guard = makeGuard(makeRepository(makeToken(expiresAt: null)), makeCurrentRequest('Bearer valid-token'), $user);

    expect($guard->user())->toBe($user);
});

it('resolves the user for a token whose expiresAt is in the future', function (): void {
    $user = new FakeAuthenticatable(id: 1);
    $guard = makeGuard(
        makeRepository(makeToken(expiresAt: '2026-01-01 13:00:00')),
        makeCurrentRequest('Bearer valid-token'),
        $user,
    );

    expect($guard->user())->toBe($user);
});

it('treats a token whose expiresAt is in the past as unauthenticated and returns no user', function (): void {
    $guard = makeGuard(
        makeRepository(makeToken(expiresAt: '2026-01-01 11:00:00')),
        makeCurrentRequest('Bearer expired-token'),
        new FakeAuthenticatable(id: 1),
    );

    expect($guard->user())->toBeNull()
        ->and($guard->check())->toBeFalse();
});

it('accepts a token one second before it expires', function (): void {
    $user = new FakeAuthenticatable(id: 1);
    $guard = makeGuard(
        makeRepository(makeToken(expiresAt: '2026-01-01 12:00:00')),
        makeCurrentRequest('Bearer almost-expired-token'),
        $user,
        now: '2026-01-01 11:59:59',
    );

    expect($guard->user())->toBe($user);
});

it('rejects a token once the clock passes its expiry', function (): void {
    $clock = new FakeClock('2026-01-01 11:59:59');
    $clock->travel('+2 seconds');

    $guard = new TokenGuard(
        repository: makeRepository(makeToken(expiresAt: '2026-01-01 12:00:00')),
        currentRequest: makeCurrentRequest('Bearer just-expired-token'),
        clock: $clock,
        provider: makeUserProvider(new FakeAuthenticatable(id: 1)),
    );

    expect($guard->user())->toBeNull();
});

it('returns false from hasAbility when the resolved token has expired', function (): void {
    $guard = makeGuard(
        makeRepository(makeToken(expiresAt: '2026-01-01 11:00:00', abilities: json_encode(['read']))),
        makeCurrentRequest('Bearer expired-token'),
        new FakeAuthenticatable(id: 1),
    );

    expect($guard->hasAbility('read'))->toBeFalse();
});

it('preserves the timing-safe SHA-256 hash lookup when resolving a token', function (): void {
    $rawToken = 'my-raw-token';
    $capturedHash = null;
    $repository = new class ($capturedHash) implements TokenRepositoryInterface
    {
        public function __construct(
            /** @noinspection PhpPropertyOnlyWrittenInspection - Reference property captures hash */
            private ?string &$capturedHash,
        ) {}

        public function find(int $id): ?PersonalAccessToken
        {
            return null;
        }

        public function findByToken(string $tokenHash): ?PersonalAccessToken
        {
            $this->capturedHash = $tokenHash;

            return makeToken();
        }

        public function create(PersonalAccessToken $token): PersonalAccessToken
        {
            return $token;
        }

        public function revoke(int $id): void {}

        public function revokeAllForUser(
            string $type,
            int|string $id,
        ): void {}
    };

    makeGuard($repository, makeCurrentRequest('Bearer ' . $rawToken), new FakeAuthenticatable(id: 1))->user();

    expect($capturedHash)->toBe(hash('sha256', $rawToken));
});

it('re-resolves the user when the current request changes', function (): void {
    $user = new FakeAuthenticatable(id: 1);
    $currentRequest = makeCurrentRequest('Bearer valid-token');
    $guard = makeGuard(makeRepository(makeToken()), $currentRequest, $user);

    $first = $guard->user();
    $currentRequest->set(makeRequest());
    $second = $guard->user();
    $currentRequest->set(makeRequest('Bearer valid-token'));
    $third = $guard->user();

    expect($first)->toBe($user)
        ->and($second)->toBeNull()
        ->and($third)->toBe($user);
});

describe('stateful methods', function (): void {
    it('throws a stateless guard error from attempt, login, loginById and logout naming TokenManager', function (
        string $method,
        callable $call,
    ): void {
        $guard = makeGuard(makeRepository(), makeCurrentRequest(), name: 'api');

        try {
            $call($guard);
            $this->fail('Expected StatelessGuardException');
        } catch (StatelessGuardException $exception) {
            expect($exception)->toBeInstanceOf(AuthException::class)
                ->and($exception->getMessage())->toBe("Cannot call $method() on token guard 'api': token guards are stateless")
                ->and($exception->getSuggestion())->toContain('TokenManager::createToken()')
                ->and($exception->getSuggestion())->toContain('TokenManager::revokeToken()');
        }
    })->with([
        'attempt' => ['attempt', fn (TokenGuard $guard) => $guard->attempt(['email' => 'a@b.c'])],
        'login' => ['login', fn (TokenGuard $guard) => $guard->login(new FakeAuthenticatable(id: 1))],
        'loginById' => ['loginById', fn (TokenGuard $guard) => $guard->loginById(1)],
        'logout' => ['logout', fn (TokenGuard $guard) => $guard->logout()],
    ]);
});

describe('failed authentication events', function (): void {
    it('dispatches TokenAuthenticationFailedEvent with reason expired for an expired token without the token value', function (): void {
        $events = new FakeEventDispatcher();
        $guard = makeGuard(
            makeRepository(makeToken(expiresAt: '2026-01-01 11:00:00')),
            makeCurrentRequest('Bearer expired-secret-token'),
            new FakeAuthenticatable(id: 1),
            eventDispatcher: $events,
            name: 'api',
        );

        $guard->check();
        $guard->user();
        $guard->hasAbility('read');

        $dispatched = $events->dispatched(TokenAuthenticationFailedEvent::class);

        expect($dispatched)->toHaveCount(1)
            ->and($dispatched[0]->reason)->toBe(TokenFailureReason::Expired)
            ->and($dispatched[0]->guard)->toBe('api')
            ->and($dispatched[0]->tokenId)->toBe(5)
            ->and($dispatched[0]->ipAddress)->toBe('203.0.113.9')
            ->and(print_r($dispatched[0], true))->not->toContain('expired-secret-token')
            ->and(print_r($dispatched[0], true))->not->toContain(hash('sha256', 'expired-secret-token'));
    });

    it('dispatches TokenAuthenticationFailedEvent with reason invalid for an unknown token', function (): void {
        $events = new FakeEventDispatcher();
        $guard = makeGuard(makeRepository(), makeCurrentRequest('Bearer unknown-token'), eventDispatcher: $events);

        $guard->user();

        $dispatched = $events->dispatched(TokenAuthenticationFailedEvent::class);

        expect($dispatched)->toHaveCount(1)
            ->and($dispatched[0]->reason)->toBe(TokenFailureReason::Invalid)
            ->and($dispatched[0]->tokenId)->toBeNull()
            ->and(print_r($dispatched[0], true))->not->toContain('unknown-token');
    });

    it('does not dispatch an event for a successful authentication or a missing token', function (): void {
        $events = new FakeEventDispatcher();
        $currentRequest = makeCurrentRequest('Bearer valid-token');
        $guard = makeGuard(makeRepository(makeToken()), $currentRequest, new FakeAuthenticatable(id: 1), eventDispatcher: $events);

        $guard->user();
        $currentRequest->set(makeRequest());
        $guard->user();

        expect($events->dispatched)->toBeEmpty();
    });
});
