<?php

namespace App\Controller;

use App\Security\IndicoAuthenticator;
use App\Security\IndicoClient;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationUtils;

class SecurityController extends AbstractController
{
    #[Route('/login', name: 'app_login')]
    public function login(AuthenticationUtils $authenticationUtils): Response
    {
        return $this->render('security/login.html.twig', [
            'error' => $authenticationUtils->getLastAuthenticationError(),
        ]);
    }

    #[Route('/sso/login', name: 'sso_login')]
    public function ssoLogin(Request $request, IndicoClient $indico): RedirectResponse
    {
        $state = bin2hex(random_bytes(16));
        $verifier = bin2hex(random_bytes(32));

        $session = $request->getSession();
        $session->set(IndicoAuthenticator::SESSION_STATE, $state);
        $session->set(IndicoAuthenticator::SESSION_VERIFIER, $verifier);

        $redirectUri = $this->generateUrl('sso_check', [], UrlGeneratorInterface::ABSOLUTE_URL);

        return $this->redirect($indico->getAuthorizationUrl($redirectUri, $state, $verifier));
    }

    #[Route('/sso/check', name: 'sso_check')]
    public function ssoCheck(): void
    {
        throw new \LogicException('This method can be blank - it will be intercepted by IndicoAuthenticator.');
    }

    #[Route('/logout', name: 'app_logout')]
    public function logout(): void
    {
        throw new \LogicException('This method can be blank - it will be intercepted by the logout key on your firewall.');
    }
}
