<?php

namespace BarnabyWalters\Indieauth\Listener;

use Symfony\Component\HttpFoundation\Request,
    Symfony\Component\Security\Http\Firewall\AbstractAuthenticationListener;
use BarnabyWalters\Indieauth\Token\IndieauthToken;

/**
 * @todo add a check for ?token somewhere, not sure where is the most useful place though
 */
class IndieauthListener extends AbstractAuthenticationListener {
    
    public function requiresAuthentication(Request $request)
    {
        return $request->query->has('token');
    }
    
    public function attemptAuthentication(Request $request) {
        // New user (not session or anon) — create an Indieauth Token
        
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