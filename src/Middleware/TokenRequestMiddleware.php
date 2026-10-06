<?php

declare(strict_types=1);

namespace Marko\AuthenticationToken\Middleware;

use Marko\AuthenticationToken\Http\CurrentRequest;
use Marko\Routing\Http\Request;
use Marko\Routing\Http\Response;
use Marko\Routing\Middleware\MiddlewareInterface;

/**
 * Global middleware that hands the inbound request to CurrentRequest for the
 * token guard, and clears it once the request is done (even when the
 * pipeline throws), so a long-running worker never authenticates a later
 * request with an earlier request's token.
 */
readonly class TokenRequestMiddleware implements MiddlewareInterface
{
    public function __construct(
        private CurrentRequest $currentRequest,
    ) {}

    public function handle(
        Request $request,
        callable $next,
    ): Response {
        $this->currentRequest->set($request);

        try {
            return $next($request);
        } finally {
            $this->currentRequest->reset();
        }
    }
}
