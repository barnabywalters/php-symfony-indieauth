<?php

namespace BarnabyWalters\Indieauth\Tests;

use Symfony\Component\Security;
use Symfony\Component\HttpKernel;

/**
 * IndieauthListenerTest
 *
 * These tests are not written and, as the dependencies are so convoluted, it’s 
 * a bit awkward setting it all up outside an app environment. So I’m delaying
 * writing these properly until I’ve got a spare day or so.
 * 
 * @author Barnaby Walters
 * @todo implement all these, and the other tests
 */
class IndieauthListenerTest extends PHPUnit_Framework_Testcase {
    public function testRequiresAuthenticationForRequestsWithTokenQueryParam() {
        // Create mocks
        $securityContext = $this->getMock('Symfony\Component\Security\Core\SecurityContext');
        $authManager = $this->getMock('Symfony\Component\Security\Core\Authentication\AuthenticationManager');
        $sessionStrategy = $this->getMock('Symfony\Component\Security\Http\Session\SessionAuthenticationStrategyInterface');
        $httpUtils = new Security\Http\HttpUtils;
        $successHandler = new Security\Http\Authentication\DefaultAuthenticationSuccessHandler($httpUtils, []);
        $failureHandler = new Security\Http\Authentication\DefaultAuthenticationFailureHandler($kernel, $httpUtils, []);
    }
}

// EOF