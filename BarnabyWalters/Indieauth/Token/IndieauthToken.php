<?php

namespace BarnabyWalters\Indieauth\Token;

use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;

/**
 * IndieauthToken
 * 
 * This is an extension of AnonymousToken with a constructor which only accepts
 * a single parameter, the token to use with the indieauth provider.
 * 
 * @author Barnaby Walters http://waterpigs.co.uk <barnaby@waterpigs.co.uk>
 */
class IndieauthToken extends UsernamePasswordToken {
    
    /**
     * Construct
     * @param string $token
     */
    public function __construct($token, $roles=array('ROLE_USER'), $user = '') {
        parent::__construct($user, $token, 'rememberMeProviderKey', $roles);
    }
}

// EOF