<?php

declare(strict_types=1);

namespace Marko\AuthenticationToken\Tests\Exceptions;

use DateTimeImmutable;
use Exception;
use Marko\AuthenticationToken\Exceptions\ExpiredTokenException;

it('throws ExpiredTokenException with context and suggestion for expired tokens', function (): void {
    $expiredAt = new DateTimeImmutable('2025-01-01 00:00:00');

    $exception = ExpiredTokenException::forToken(7, $expiredAt);

    expect($exception)->toBeInstanceOf(ExpiredTokenException::class)
        ->and($exception)->toBeInstanceOf(Exception::class)
        ->and($exception->getMessage())->not->toBeEmpty()
        ->and($exception->getContext())->toContain('Token #7')
        ->and($exception->getContext())->toContain('2025-01-01')
        ->and($exception->getSuggestion())->not->toBeEmpty();
});

it('never includes the plain-text token in ExpiredTokenException', function (): void {
    $exception = ExpiredTokenException::forToken(null, new DateTimeImmutable('2025-01-01 00:00:00'));

    expect($exception->getContext())->toBe('The token expired at 2025-01-01 00:00:00');
});
