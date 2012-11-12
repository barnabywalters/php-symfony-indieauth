<?php

namespace BarnabyWalters\Indieauth\Provider;

use Symfony\Component\Security\Core\Authentication\Provider\AuthenticationProviderInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use BarnabyWalters\Indieauth\Token\IndieauthToken;
use Guzzle\Http\Client;

class IndieauthProvider implements AuthenticationProviderInterface {

    private $userProvider;
    private $cacheDir;
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

    public function supports(TokenInterface $token) {
        return $token instanceof IndieauthToken;
    }
    
    public function supportsClass($class) {
        return $class === 'IndieauthToken';
    }

    /**
     * Authenticate
     * 
     * Given a token, try to authenticate it against $this->authServer
     * 
     * @param \Symfony\Component\Security\Core\Authentication\Token\TokenInterface $token
     * @return \app\libs\Indieauth\Token\IndieauthToken
     * @throws AuthenticationException
     * @todo for some reason this is being called multiple times, with no credentials on the second time
     */
    public function authenticate(TokenInterface $token) {
        /* @var $client Guzzle\Http\Client */
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
        } catch (EEEGuzzle\Http\Exception\ClientErrorResponseException $e) {
            throw new AuthenticationException('Authenticating token with indieauth.com failed: ' . print_r($e, true));
        }
    }
}