<?php

namespace App\Security;

use App\Entity\User;
use Doctrine\ORM\EntityManagerInterface;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpKernel\Exception\ServiceUnavailableHttpException;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Http\AccessToken\AccessTokenHandlerInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Contracts\Cache\CacheInterface;
use Symfony\Contracts\Cache\ItemInterface;
use Symfony\Contracts\HttpClient\Exception\ClientExceptionInterface;
use Symfony\Contracts\HttpClient\Exception\DecodingExceptionInterface;
use Symfony\Contracts\HttpClient\Exception\ExceptionInterface;

/**
 * Authenticates API requests with an Indico token (OAuth or personal) that has
 * the read:user scope.
 *
 * Only users who have already signed in to the website can use the API: a token
 * never creates or links an account, because it may have been issued to any
 * Indico application. Roles always come from the users table.
 */
class IndicoAccessTokenHandler implements AccessTokenHandlerInterface
{
    // Bounds both the load on Indico and how long a revoked token keeps working.
    private const CACHE_SECONDS = 60;

    public function __construct(
        private readonly IndicoClient $indico,
        private readonly CacheInterface $cache,
        private readonly EntityManagerInterface $entityManager,
        private readonly LoggerInterface $logger,
    ) {
    }

    public function getUserBadgeFrom(#[\SensitiveParameter] string $accessToken): UserBadge
    {
        $indicoId = $this->resolveIndicoId($accessToken);

        return new UserBadge('indico:'.$indicoId, fn () => $this->entityManager
            ->getRepository(User::class)
            ->findOneBy(['indicoId' => $indicoId]));
    }

    private function resolveIndicoId(string $accessToken): int
    {
        try {
            return $this->cache->get(
                'indico_token_'.hash('sha256', $accessToken),
                function (ItemInterface $item) use ($accessToken): int {
                    $item->expiresAfter(self::CACHE_SECONDS);

                    return $this->indico->fetchTokenUser($accessToken)['id'];
                }
            );
        } catch (ClientExceptionInterface|DecodingExceptionInterface|\UnexpectedValueException $e) {
            // Indico answers 401 for a bad token, and "null" for tokens it does not resolve to a user.
            throw new BadCredentialsException('Invalid Indico token.', 0, $e);
        } catch (ExceptionInterface $e) {
            $this->logger->error('Could not reach Indico to validate an API token.', ['exception' => $e]);

            throw new ServiceUnavailableHttpException(null, 'Indico is unavailable.', $e);
        }
    }
}
