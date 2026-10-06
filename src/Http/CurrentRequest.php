<?php

declare(strict_types=1);

namespace Marko\AuthenticationToken\Http;

use Marko\Core\Contracts\ResettableInterface;
use Marko\Routing\Http\Request;

/**
 * Holds the HTTP request being handled, so the token guard can read its
 * Authorization header. The Request is not a container service, so
 * TokenRequestMiddleware (global middleware) sets it here for the duration
 * of each request. Outside a request (CLI, queue jobs) it holds nothing and
 * the token guard treats the caller as a guest.
 */
class CurrentRequest implements ResettableInterface
{
    private ?Request $request = null;

    public function set(
        Request $request,
    ): void {
        $this->request = $request;
    }

    public function get(): ?Request
    {
        return $this->request;
    }

    public function reset(): void
    {
        $this->request = null;
    }
}
