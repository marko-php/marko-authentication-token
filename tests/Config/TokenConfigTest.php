<?php

declare(strict_types=1);

namespace Marko\AuthenticationToken\Tests\Config;

use Marko\AuthenticationToken\Config\TokenConfig;
use Marko\Config\ConfigRepository;
use Marko\Config\Exceptions\ConfigException;
use Marko\Config\Exceptions\ConfigNotFoundException;

function tokenConfigWith(
    mixed $expirationDays,
): TokenConfig {
    return new TokenConfig(
        config: new ConfigRepository([
            'authentication-token' => ['token_expiration_days' => $expirationDays],
        ]),
    );
}

it('returns 365 days for the shipped config', function (): void {
    $config = new TokenConfig(
        config: new ConfigRepository([
            'authentication-token' => require dirname(__DIR__, 2) . '/config/authentication-token.php',
        ]),
    );

    expect($config->expirationDays())->toBe(365);
});

it('returns the configured number of days', function (): void {
    expect(tokenConfigWith(30)->expirationDays())->toBe(30);
});

it('returns null when token_expiration_days is null so tokens never expire by default', function (): void {
    expect(tokenConfigWith(null)->expirationDays())->toBeNull();
});

it('throws a ConfigException when token_expiration_days is zero or negative', function (int $days): void {
    expect(fn (): ?int => tokenConfigWith($days)->expirationDays())
        ->toThrow(ConfigException::class, 'must be a positive integer or null');
})->with([0, -1]);

it('throws a ConfigException when token_expiration_days is not an integer', function (mixed $days): void {
    expect(fn (): ?int => tokenConfigWith($days)->expirationDays())
        ->toThrow(ConfigException::class, 'must be a positive integer or null');
})->with(['365', 1.5, true]);

it('throws ConfigNotFoundException when token_expiration_days is missing', function (): void {
    $config = new TokenConfig(
        config: new ConfigRepository(['authentication-token' => []]),
    );

    expect(fn (): ?int => $config->expirationDays())->toThrow(ConfigNotFoundException::class);
});
