<?php

namespace App\Security;

use Symfony\Contracts\HttpClient\Exception\ExceptionInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;

/**
 * Talks to Indico's OAuth 2 provider.
 *
 * Indico is not an OpenID Connect provider: it issues no ID token and has no
 * userinfo endpoint, so the identity comes from its /api/user/ endpoint, which
 * requires the read:user scope.
 */
class IndicoClient
{
    private const TIMEOUT_SECONDS = 10;

    public function __construct(
        private readonly HttpClientInterface $httpClient,
        private readonly string $indicoBaseUrl,
        private readonly string $indicoAppId,
        private readonly string $indicoAppSecret,
        private readonly string $indicoScopes,
    ) {
    }

    public function getAuthorizationUrl(string $redirectUri, string $state, string $codeVerifier): string
    {
        $challenge = rtrim(strtr(base64_encode(hash('sha256', $codeVerifier, true)), '+/', '-_'), '=');

        return $this->url('/oauth/authorize').'?'.http_build_query([
            'response_type' => 'code',
            'client_id' => $this->indicoAppId,
            'redirect_uri' => $redirectUri,
            'scope' => $this->indicoScopes,
            'state' => $state,
            'code_challenge' => $challenge,
            'code_challenge_method' => 'S256',
        ], '', '&', PHP_QUERY_RFC3986);
    }

    /**
     * Exchanges an authorization code for the Indico user it was issued to.
     *
     * @return array{id: int, email: string}
     *
     * @throws ExceptionInterface        when Indico rejects a request or returns something other than a JSON object
     * @throws \UnexpectedValueException when the response does not identify a user
     */
    public function fetchUser(string $code, string $redirectUri, string $codeVerifier): array
    {
        $token = $this->httpClient->request('POST', $this->url('/oauth/token'), [
            'timeout' => self::TIMEOUT_SECONDS,
            'headers' => ['Accept' => 'application/json'],
            'body' => [
                'grant_type' => 'authorization_code',
                'code' => $code,
                'redirect_uri' => $redirectUri,
                'client_id' => $this->indicoAppId,
                'client_secret' => $this->indicoAppSecret,
                'code_verifier' => $codeVerifier,
            ],
        ])->toArray();

        if (!\is_string($token['access_token'] ?? null)) {
            throw new \UnexpectedValueException('Indico token response has no access_token.');
        }

        return $this->fetchTokenUser($token['access_token']);
    }

    /**
     * Returns the Indico user an access token belongs to.
     *
     * @return array{id: int, email: string}
     *
     * @throws ExceptionInterface        when Indico rejects the token or returns something other than a JSON object
     * @throws \UnexpectedValueException when the response does not identify a user
     */
    public function fetchTokenUser(#[\SensitiveParameter] string $accessToken): array
    {
        $user = $this->httpClient->request('GET', $this->url('/api/user/'), [
            'timeout' => self::TIMEOUT_SECONDS,
            'auth_bearer' => $accessToken,
        ])->toArray();

        if (!\is_int($user['id'] ?? null) || !\is_string($user['email'] ?? null) || '' === $user['email']) {
            throw new \UnexpectedValueException('Indico user response has no id or email.');
        }

        return ['id' => $user['id'], 'email' => $user['email']];
    }

    private function url(string $path): string
    {
        return rtrim($this->indicoBaseUrl, '/').$path;
    }
}
