<?php

namespace BarnabyWalters\Indieauth\Token;

use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\User\UserInterface;

/**
 * IndieauthToken
 * 
 * This is an extremely light extension of UsernamePasswordToken (where most of 
 * the business logic takes place). The only wrapping is in the constructor,
 * which accepts at minimum a token (such as one returned by an indieauth 
 * callback), and can optionally accept an array of roles and a user object.
 * 
 * @author Barnaby Walters http://waterpigs.co.uk <barnaby@waterpigs.co.uk>
 */
class IndieauthToken extends UsernamePasswordToken {
    
    /**
     * Construct
     * 
     * @param string $token An indieauth token
     * @param array $roles An array of roles to assign to the user
     * @param string|UserInterface $user A user object to attach to the token
     */
    public function __construct($token, $roles=array('ROLE_USER'), $user = '') {
        parent::__construct($user, $token, 'rememberMeProviderKey', $roles);
    }
}

// EOF