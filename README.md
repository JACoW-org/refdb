JaCoW Reference Search Engine
========================

Requirements: PHP 8.1

## API authentication

Send an Indico token with the `read:user` scope, either personal or OAuth:

    Authorization: Bearer <token>

Its owner must have signed in to this website at least once, and write routes
need `ROLE_ADMIN` in the users table. Token validity is cached for 60 seconds.
