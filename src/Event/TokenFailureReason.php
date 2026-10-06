<?php

declare(strict_types=1);

namespace Marko\AuthenticationToken\Event;

/**
 * Why a presented bearer token did not authenticate.
 */
enum TokenFailureReason: string
{
    /** No stored token matches the presented one (unknown or revoked). */
    case Invalid = 'invalid';

    /** The token exists but its expiry has passed. */
    case Expired = 'expired';
}
