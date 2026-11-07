<?php

namespace App\Security;

use App\Entity\User;
use Doctrine\ORM\EntityManagerInterface;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;
use Symfony\Component\Security\Http\Authenticator\AbstractAuthenticator;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;
use Symfony\Component\Security\Http\EntryPoint\AuthenticationEntryPointInterface;
use Symfony\Component\Security\Http\SecurityRequestAttributes;
use Symfony\Component\Security\Http\Util\TargetPathTrait;
use Symfony\Contracts\HttpClient\Exception\ExceptionInterface;

/**
 * Completes the Indico sign-in started by SecurityController::ssoLogin().
 */
class IndicoAuthenticator extends AbstractAuthenticator implements AuthenticationEntryPointInterface
{
    use TargetPathTrait;

    public const SESSION_STATE = 'indico_oauth_state';
    public const SESSION_VERIFIER = 'indico_oauth_verifier';

    private const SIGN_IN_FAILED = 'Sign-in with Indico failed. Please try again.';

    public function __construct(
        private readonly IndicoClient $indico,
        private readonly EntityManagerInterface $entityManager,
        private readonly UrlGeneratorInterface $urlGenerator,
        private readonly LoggerInterface $logger,
    ) {
    }

    public function supports(Request $request): bool
    {
        return 'sso_check' === $request->attributes->get('_route');
    }

    public function authenticate(Request $request): Passport
    {
        $session = $request->getSession();
        // Both values are single use, so a replayed callback fails the state check.
        $state = $session->remove(self::SESSION_STATE);
        $verifier = $session->remove(self::SESSION_VERIFIER);

        if (!\is_string($state) || !\is_string($verifier) || !hash_equals($state, $request->query->getString('state'))) {
            throw new CustomUserMessageAuthenticationException('Your sign-in attempt expired. Please try again.');
        }

        if ($request->query->has('error')) {
            $this->logger->warning('Indico refused the authorization request.', [
                'error' => $request->query->getString('error'),
                'description' => $request->query->getString('error_description'),
            ]);

            throw new CustomUserMessageAuthenticationException(self::SIGN_IN_FAILED);
        }

        $code = $request->query->getString('code');
        if ('' === $code) {
            throw new CustomUserMessageAuthenticationException(self::SIGN_IN_FAILED);
        }

        $redirectUri = $this->urlGenerator->generate('sso_check', [], UrlGeneratorInterface::ABSOLUTE_URL);

        try {
            $indicoUser = $this->indico->fetchUser($code, $redirectUri, $verifier);
        } catch (ExceptionInterface|\UnexpectedValueException $e) {
            $this->logger->error('Could not fetch the user from Indico.', ['exception' => $e]);

            throw new CustomUserMessageAuthenticationException(self::SIGN_IN_FAILED, [], 0, $e);
        }

        $user = $this->findOrCreateUser($indicoUser['id'], $indicoUser['email']);

        return new SelfValidatingPassport(new UserBadge($user->getUserIdentifier(), static fn () => $user));
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): Response
    {
        $session = $request->getSession();
        $target = $this->getTargetPath($session, $firewallName);
        $this->removeTargetPath($session, $firewallName);

        return new RedirectResponse($target ?? $this->urlGenerator->generate('homepage'));
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): Response
    {
        $request->getSession()->set(SecurityRequestAttributes::AUTHENTICATION_ERROR, $exception);

        return new RedirectResponse($this->urlGenerator->generate('app_login'));
    }

    public function start(Request $request, ?AuthenticationException $authException = null): Response
    {
        return new RedirectResponse($this->urlGenerator->generate('app_login'));
    }

    /**
     * Users are matched on their Indico id. The first sign-in of an account
     * that predates Indico links it by email address; roles stay managed here.
     */
    private function findOrCreateUser(int $indicoId, string $email): User
    {
        $repository = $this->entityManager->getRepository(User::class);

        $user = $repository->findOneBy(['indicoId' => $indicoId]);
        if (null !== $user) {
            return $user;
        }

        // The column collation also treats accented letters as equal, which must not link accounts.
        $matches = array_values(array_filter(
            $repository->findBy(['email' => $email]),
            static fn (User $candidate) => mb_strtolower($candidate->getEmail()) === mb_strtolower($email),
        ));

        if (\count($matches) > 1 || (1 === \count($matches) && null !== $matches[0]->getIndicoId())) {
            $this->logger->warning('Indico sign-in matches an ambiguous local account.', ['indicoId' => $indicoId]);

            throw new CustomUserMessageAuthenticationException('Your Indico account could not be matched to a unique account here. Please contact an administrator.');
        }

        $user = $matches[0] ?? (new User())
            ->setUsername('indico_'.$indicoId)
            ->setEmail($email)
            ->setEnabled(true);

        $user->setIndicoId($indicoId);
        $this->entityManager->persist($user);
        $this->entityManager->flush();

        return $user;
    }
}
