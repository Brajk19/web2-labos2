<?php

declare(strict_types=1);

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\TooManyRequestsHttpException;
use Symfony\Component\RateLimiter\RateLimiterFactory;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Core\Exception\TooManyLoginAttemptsAuthenticationException;

class WelcomeController extends AbstractController
{
    public function __construct(
        private readonly RequestStack $requestStack
    ) {
    }

    #[Route('/', name: 'welcome')]
    public function index(Request $request): Response
    {
        $this->requestStack
            ->getSession()
            ->set('sessionID', 'top-secret-id');

        $response = new Response();
        $response->headers->setCookie(
            Cookie::create('labos2-session')
                ->withValue('top-secret-session-'.(string)random_int(1000, 9999))
                ->withExpires(new \DateTimeImmutable('+1 week'))
                ->withSecure(false)
                ->withHttpOnly(false)
        );

        return $this->render(
            'welcome/index.html.twig',
            ['name' => $request->query->get('name', '-')],
            $response
        );
    }

    #[Route('/welcome', name: 'xss_page')]
    public function xssTest(Request $request): Response
    {
        $name = $request->query->get('name');

        if($request->query->get('xss-safe')) {
            $name = htmlentities($name);
        }

        return $this->render('welcome/xss.html.twig', [
            'name' => $name
        ]);
    }

    #[Route('/fake-login', name: 'login_page', methods: ['GET'])]
    public function brokenAuthentificationTest(
        Request $request,
        RateLimiterFactory $labosLoginLimiter
    ): Response {
        $limitEnabled = $request->query->getBoolean('enableRateLimit');

        if($limitEnabled) {
            $limiter = $labosLoginLimiter->create($request->getClientIp());

            if(false === $limiter->consume()->isAccepted()) {
                throw new TooManyRequestsHttpException();
            }
        }


        if('admin' === $request->query->get('username') && 'maverick' === $request->query->get('password')) {
            return new JsonResponse([
                'status' => 'Success'
            ]);
        }

        throw new BadCredentialsException();
    }

    #[Route('/reset-rate-limiter', name: 'reset_rate_limiter', methods: ['POST'])]
    public function resetRateLimiter(
        Request $request,
        RateLimiterFactory $labosLoginLimiter
    ): Response {
        $limiter = $labosLoginLimiter->create($request->getClientIp());
        $limiter->reset();

        return new Response(
            'Reset completed',
            Response::HTTP_NO_CONTENT
        );
    }
}
