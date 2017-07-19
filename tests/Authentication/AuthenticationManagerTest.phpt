<?php declare(strict_types = 1);

namespace GrandMediaTests\Security\Authentication;

use GrandMedia\Security\Authentication\AuthenticationManager;
use GrandMedia\Security\Authentication\IAuthenticator;
use GrandMediaTests\Security\Authentication\Mocks\Authenticator;
use GrandMediaTests\Security\Authentication\Mocks\Credentials;
use GrandMediaTests\Security\Authentication\Mocks\Identity;
use GrandMediaTests\Security\Authentication\Mocks\UserStorage;
use Nette\Security\AuthenticationException;
use Tester\Assert;
use Tester\TestCase;

require_once __DIR__ . '/../bootstrap.php';

final class AuthenticationManagerTest extends TestCase
{
	const DEACTIVATED_USER_NAME = 'foo';
	const DEACTIVATED_USER_PASSWORD = 'foo';
	const ACTIVE_USER_NAME = 'bar';
	const ACTIVE_USER_PASSWORD = 'bar';
	const FAKE_USER_NAME = 'baz';
	const FAKE_USER_PASSWORD = 'baz';

	const STAY_SIGNED_IN_TIME = '14 days';
	const DO_NOT_STAY_SIGNED_IN_TIME = '20 minutes';

	public function testLogin()
	{
		$eventCounter = (object)[
			'login' => 0,
			'logout' => 0,
		];
		$userStorage = new UserStorage();
		$manager = $this->createManager($userStorage, $eventCounter);

		$deactivatedIdentity = new Identity(self::DEACTIVATED_USER_NAME, self::DEACTIVATED_USER_PASSWORD);
		$deactivatedIdentity->deactivate();
		$activeIdentity = new Identity(self::ACTIVE_USER_NAME, self::ACTIVE_USER_PASSWORD);
		$authenticator = new Authenticator(
			[
				$deactivatedIdentity,
				$activeIdentity,
			]
		);

		Assert::false($manager->isUserLoggedIn());
		Assert::null($manager->getIdentity());

		Assert::exception(
			function () use ($manager, $authenticator) {
				$manager->login($authenticator, new Credentials(self::FAKE_USER_NAME, self::FAKE_USER_PASSWORD), true);
			},
			AuthenticationException::class,
			'',
			IAuthenticator::IDENTITY_NOT_FOUND
		);

		Assert::exception(
			function () use ($manager, $authenticator) {
				$manager->login(
					$authenticator,
					new Credentials(self::ACTIVE_USER_NAME, self::FAKE_USER_PASSWORD),
					true
				);
			},
			AuthenticationException::class,
			'',
			IAuthenticator::INVALID_CREDENTIAL
		);

		Assert::exception(
			function () use ($manager, $authenticator) {
				$manager->login(
					$authenticator,
					new Credentials(self::DEACTIVATED_USER_NAME, self::DEACTIVATED_USER_PASSWORD),
					true
				);
			},
			AuthenticationException::class,
			'',
			IAuthenticator::NOT_APPROVED
		);

		Assert::false($manager->isUserLoggedIn());
		Assert::null($manager->getIdentity());
		Assert::same(0, $eventCounter->login);
		Assert::same(0, $eventCounter->logout);

		$manager->login($authenticator, new Credentials(self::ACTIVE_USER_NAME, self::ACTIVE_USER_PASSWORD), true);
		Assert::same(1, $eventCounter->login);
		Assert::same(0, $eventCounter->logout);
		Assert::true($manager->isUserLoggedIn());
		Assert::same($activeIdentity, $manager->getIdentity());
		Assert::same(self::STAY_SIGNED_IN_TIME, $userStorage->getExpiration());

		$manager->login($authenticator, new Credentials('bar', 'bar'), false);
		Assert::same(2, $eventCounter->login);
		Assert::same(1, $eventCounter->logout);
		Assert::true($manager->isUserLoggedIn());
		Assert::same($activeIdentity, $manager->getIdentity());
		Assert::same(self::DO_NOT_STAY_SIGNED_IN_TIME, $userStorage->getExpiration());
	}

	public function testLogout()
	{
		$eventCounter = (object)[
			'login' => 0,
			'logout' => 0,
		];
		$userStorage = new UserStorage();
		$manager = $this->createManager($userStorage, $eventCounter);

		$activeIdentity = new Identity(self::ACTIVE_USER_NAME, self::ACTIVE_USER_PASSWORD);
		$authenticator = new Authenticator(
			[
				$activeIdentity,
			]
		);

		$manager->logout();
		Assert::same(0, $eventCounter->logout);

		$manager->login($authenticator, new Credentials(self::ACTIVE_USER_NAME, self::ACTIVE_USER_PASSWORD), true);
		$manager->logout();
		Assert::false($manager->isUserLoggedIn());
		Assert::same(1, $eventCounter->logout);
		Assert::same($activeIdentity, $manager->getIdentity());

		$manager->login($authenticator, new Credentials(self::ACTIVE_USER_NAME, self::ACTIVE_USER_PASSWORD), true);
		$manager->logout(true);
		Assert::false($manager->isUserLoggedIn());
		Assert::same(2, $eventCounter->logout);
		Assert::null($manager->getIdentity());
	}

	private function createManager(UserStorage $userStorage, $eventCounter): AuthenticationManager
	{
		$manager = new AuthenticationManager($userStorage, self::STAY_SIGNED_IN_TIME, self::DO_NOT_STAY_SIGNED_IN_TIME);

		$manager->onLoggedIn[] = function () use ($eventCounter) {
			$eventCounter->login++;
		};
		$manager->onLoggedOut[] = function () use ($eventCounter) {
			$eventCounter->logout++;
		};

		return $manager;
	}
}

(new AuthenticationManagerTest())->run();
