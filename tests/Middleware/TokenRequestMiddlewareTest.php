<?php

declare(strict_types=1);

namespace Marko\AuthenticationToken\Tests\Middleware;

use Marko\AuthenticationToken\Http\CurrentRequest;
use Marko\AuthenticationToken\Middleware\TokenRequestMiddleware;
use Marko\Core\Contracts\ResettableInterface;
use Marko\Routing\Http\Request;
use Marko\Routing\Http\Response;
use RuntimeException;

it('hands the request to CurrentRequest while the request is handled', function (): void {
    $currentRequest = new CurrentRequest();
    $request = new Request();
    $seen = null;

    new TokenRequestMiddleware($currentRequest)->handle(
        $request,
        function (Request $r) use ($currentRequest, &$seen): Response {
            $seen = $currentRequest->get();

            return new Response();
        },
    );

    expect($seen)->toBe($request)
        ->and($currentRequest->get())->toBeNull();
});

it('clears CurrentRequest after the request even when the pipeline throws', function (): void {
    $currentRequest = new CurrentRequest();

    try {
        new TokenRequestMiddleware($currentRequest)->handle(
            new Request(),
            fn (Request $r): Response => throw new RuntimeException('boom'),
        );
    } catch (RuntimeException) {
        // expected
    }

    expect($currentRequest->get())->toBeNull();
});

it('is resettable so long-running workers forget the request', function (): void {
    $currentRequest = new CurrentRequest();
    $currentRequest->set(new Request());

    $currentRequest->reset();

    expect($currentRequest)->toBeInstanceOf(ResettableInterface::class)
        ->and($currentRequest->get())->toBeNull();
});
