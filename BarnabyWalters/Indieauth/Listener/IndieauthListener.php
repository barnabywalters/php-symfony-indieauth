<?php

namespace BarnabyWalters\Indieauth\Listener;

use Symfony\Component\HttpFoundation\Request,
    Symfony\Component\Security\Http\Firewall\AbstractAuthenticationListener;
use BarnabyWalters\Indieauth\Token\IndieauthToken;

/**
 * Indieauth Listener
 * 
 * This is a light extension of AbstractAuthenticationListener, which is where 
 * the bulk of the logic goes on. Don’t be put off by the rather huge constructor,
 * you get a *lot* for free.
 * 
 * @author Barnaby Walters http://waterpigs.co.uk <barnaby@waterpigs.co.uk>
 */
class IndieauthListener extends AbstractAuthenticationListener {
    
    /**
     * Requires Authentication
     * 
     * An internal method used to tell whether or not a particular request
     * requires authentication by indieauth. Specifically, it returns true if 
     * the query has a 'token' query parameter.
     * 
     * This is quite prone to collision, so I raised an issue on the indieauth 
     * software to support client-determined param name. If it is added, it will
     * be specified here by a configurable property.
     * 
     * @param \Symfony\Component\HttpFoundation\Request $request
     * @return bool Whether or not $request requires authentication
     */
    public function requiresAuthentication(Request $request)
    {
        return $request->query->has('token');
    }
    
    /**
     * Attempt Authentication
     * 
     * An internal method called by it’s parent’s `handle()` method. Given a 
     * request, tries to aithenticate it. Returns the authenticated token or 
     * throws an exception (bubbled from `authenticationManager->authenticate()`)
     * if something goes wrong.
     * 
     * @param \Symfony\Component\HttpFoundation\Request $request
     * @return \Symfony\Component\Security\Authentication\TokenInterface The authenticated token
     * @todo What to do if there is no token param? Should that conditional even be in here?
     */
    public function attemptAuthentication(Request $request) {
        if ($this->requiresAuthentication($request)) {
            if ($this->logger !== null)
                $this->logger->info('IndieauthListener found ?token param, so authenticating with indieauth');

            $token = new IndieauthToken($request->query->get('token'));
            
            $this->logger->info('Created IndieauthToken', array(
                'credentials' => $token->getCredentials(),
                'roles' => $token->getRoles(),
                'isAuthenticated' => $token->isAuthenticated()
            ));

            $authToken = $this->authenticationManager->authenticate($token);
            
            return $authToken;
        }
    }
}

// EOF