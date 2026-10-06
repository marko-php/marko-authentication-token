<?php

declare(strict_types=1);

return [
    /*
    |--------------------------------------------------------------------------
    | Token Expiration
    |--------------------------------------------------------------------------
    |
    | The default lifetime, in days, of a personal access token created
    | without an explicit expiresAt. TokenManager stores now + this many days
    | as the token's expires_at. Must be a positive integer, or null for
    | tokens that never expire unless createToken() is given an expiresAt.
    |
    */
    'token_expiration_days' => 365,
];
