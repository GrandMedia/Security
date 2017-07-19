<?php declare(strict_types = 1);

namespace GrandMediaTests\Security\Authentication;

use GrandMedia\Security\Authentication\AuthenticationManager;
use GrandMedia\Security\Authentication\AutomaticLogoutListener;
use GrandMediaTests\Security\Authentication\Mocks\Identity;
use GrandMediaTests\Security\Authentication\Mocks\UserStorage;
use Tester\Assert;
use Tester\TestCase;

require_once __DIR__ . '/../bootstrap.php';

final class AutomaticLogoutListenerTest extends TestCase
{
	public function testCheck()
	{
		$userStorage = new UserStorage();
		$identity = new Identity('foo', 'foo');
		$userStorage->setAuthenticated(true);
		$userStorage->setIdentity($identity);
		$listener = new AutomaticLogoutListener(new AuthenticationManager($userStorage, '', ''));

		$identity->deactivate();
		$listener->check();

		Assert::false($userStorage->isAuthenticated());
	}
}

(new AutomaticLogoutListenerTest())->run();
