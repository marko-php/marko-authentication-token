<?php

declare(strict_types=1);

namespace Marko\AuthenticationToken\Tests\Exceptions;

use Exception;
use Marko\AuthenticationToken\Exceptions\InvalidTokenException;

it('throws InvalidTokenException with context for malformed token format', function (): void {
    $exception = InvalidTokenException::forToken();

    expect($exception)->toBeInstanceOf(InvalidTokenException::class)
        ->and($exception)->toBeInstanceOf(Exception::class)
        ->and($exception->getMessage())->not->toBeEmpty()
        ->and($exception->getContext())->toBe('The presented token has an invalid or malformed format')
        ->and($exception->getSuggestion())->not->toBeEmpty();
});
