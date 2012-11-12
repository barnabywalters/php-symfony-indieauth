<?php

namespace BarnabyWalters\Indieauth\Provider;

use Symfony\Component\Security\Core\Authentication\Provider\AuthenticationProviderInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use BarnabyWalters\Indieauth\Token\IndieauthToken;
use Guzzle\Http\Client;

/**
 * Indieauth Provider
 * 
 * An authentication provider for use with Symfony Security component, allowing
 * IndieauthTokens to be authenticated against an indieauth server, and the 
 * corresponding user to be loaded from the specified userProvider.
 * 
 * The user provider constructor injection is written against 
 * `UserProviderInterface`, so you can use whatever one you want, but it **MUST**
 * allow the username in `loadUserByUsername` to be a URL, as that is all
 * indieauth gives us.
 * 
 * @author Barnaby Walters http://waterpigs.co.uk <barnaby@waterpigs.co.uk>
 */
class IndieauthProvider implements AuthenticationProviderInterface {

    /**
     * User Provider
     * @var UserProviderInterface
     */
    private $userProvider;
    
    /**
     * Cache Dir
     * @var string $cacheDir
     */
    private $cacheDir;
    
    /**
     * Logger
     * @var Logger
     * @todo Monolog or Symfony LoggerInterface? I think symfony is adopting Monolog
     */
    private $logger;
    
    /**
     * Indieauth Server
     * 
     * The indieauth server to authenticate the token with. Defaults to 
     * 'https://indieauth.com'
     * 
     * @var string
     */
    public $authServer = 'https://indieauth.com';
    
    /**
     * Constructor
     * @param \Symfony\Component\Security\Core\User\UserProviderInterface $userProvider
     * @param string $cacheDir
     * @param Logger $logger=null
     */
    public function __construct(UserProviderInterface $userProvider, $cacheDir, $logger=null) {
        $this->userProvider = $userProvider;
        $this->cacheDir = $cacheDir;
        $this->logger = $logger;
    }
    
    /**
     * Set Auth Server
     * 
     * Sets the indieauth server to use. $server should be a fully qualified URL,
     * e.g. 'https://indieauth.com'.
     * @param string $server
     */
    public function setAuthServer($server) {
        $this->authServer = $server;
    }
    
    /**
     * Supports
     * 
     * Given a token, returns `bool` whether or not instances of IndieauthProvider
     * can handle it. Specifically, it sees if it is an instance of 
     * `BarnabyWalters\Indieauth\Token\IndieauthToken.`
     * 
     * @param \Symfony\Component\Security\Core\Authentication\Token\TokenInterface $token
     * @return bool Whether or not this can handle $token
     */
    public function supports(TokenInterface $token) {
        return $token instanceof IndieauthToken;
    }
    
    /**
     * Supports Class
     * 
     * Given the name of a class, returns whether or not $this can handle instances
     * of $class. Specifically, it sees if it is an instance of 
     * `BarnabyWalters\Indieauth\Token\IndieauthToken.`
     * 
     * @param string $class
     * @return bool Whether or not tokens of class $class are supported
     */
    public function supportsClass($class) {
        return $class === 'BarnabyWalters\Indieauth\Token\IndieauthToken';
    }

    /**
     * Authenticate
     * 
     * Given a token, try to authenticate it against $this->authServer. If it 
     * succeeded and the corresponding user was found, return an authenticated 
     * token with a user attached.
     * 
     * If something goes wrong, an AuthenticationException is thrown.
     * 
     * @param \Symfony\Component\Security\Core\Authentication\Token\TokenInterface $token
     * @return \app\libs\Indieauth\Token\IndieauthToken
     * @throws AuthenticationException
     * @todo handle people who aren’t in my address book gracefully (in the userProvider?)
     */
    public function authenticate(TokenInterface $token) {
        /** @var $client Guzzle\Http\Client **/
        $client = new Client($this->authServer);
        
        try {
            $response = $client->get('session?token=' . $token->getCredentials())->send();
            
            $data = json_decode($response -> getBody());
            
             // Store username in this of object -- just the hostname and path, ignore protocol, query string and trailing slash
            $url = parse_url($data->me);
            $username = @trim($url['host'] . $url['path'], '/');

            $user = $this->userProvider->loadUserByUsername($username);

            $authenticatedToken = new IndieauthToken($token->getCredentials(), $user->getRoles(), $user);
            
            return $authenticatedToken;
        } catch (Guzzle\Http\Exception\ClientErrorResponseException $e) {
            throw new AuthenticationException('Authenticating token with indieauth.com failed: ' . print_r($e, true));
        }
    }
}