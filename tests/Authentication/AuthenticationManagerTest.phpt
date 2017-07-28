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

require_once __DIR__ . '/../bootstrap.php';

/**
 * @testCase
 */
final class AuthenticationManagerTest extends \Tester\TestCase
{

	private const USER_NAME = 'foo';
	private const USER_PASSWORD = 'foo';
	private const FAKE_USER_NAME = 'bar';
	private const FAKE_USER_PASSWORD = 'bar';

	private const STAY_SIGNED_IN_TIME = '14 days';
	private const DO_NOT_STAY_SIGNED_IN_TIME = '20 minutes';

	public function testLogin(): void
	{
		$eventCounter = (object) [
			'login' => 0,
			'logout' => 0,
		];
		$userStorage = new UserStorage();
		$manager = $this->createManager($userStorage, $eventCounter);

		$activeIdentity = new Identity(self::USER_NAME, self::USER_PASSWORD);
		$authenticator = new Authenticator(
			[
				$activeIdentity,
			]
		);

		Assert::false($manager->isUserLoggedIn());
		Assert::null($manager->getIdentity());

		Assert::exception(
			function () use ($manager, $authenticator) {
				$manager->login(
					$authenticator,
					new Credentials(self::FAKE_USER_NAME, self::FAKE_USER_PASSWORD),
					'',
					false
				);
			},
			AuthenticationException::class,
			'',
			IAuthenticator::IDENTITY_NOT_FOUND
		);

		Assert::exception(
			function () use ($manager, $authenticator) {
				$manager->login(
					$authenticator,
					new Credentials(self::USER_NAME, self::FAKE_USER_PASSWORD),
					'',
					false
				);
			},
			AuthenticationException::class,
			'',
			IAuthenticator::INVALID_CREDENTIAL
		);

		Assert::false($manager->isUserLoggedIn());
		Assert::null($manager->getIdentity());
		Assert::same(0, $eventCounter->login);
		Assert::same(0, $eventCounter->logout);

		$manager->login(
			$authenticator,
			new Credentials(self::USER_NAME, self::USER_PASSWORD),
			self::STAY_SIGNED_IN_TIME,
			false
		);
		Assert::same(1, $eventCounter->login);
		Assert::same(0, $eventCounter->logout);
		Assert::true($manager->isUserLoggedIn());
		Assert::same($activeIdentity, $manager->getIdentity());
		Assert::same(self::STAY_SIGNED_IN_TIME, $userStorage->getExpiration());

		$manager->login(
			$authenticator,
			new Credentials(self::USER_NAME, self::USER_PASSWORD),
			self::DO_NOT_STAY_SIGNED_IN_TIME,
			true
		);
		Assert::same(2, $eventCounter->login);
		Assert::same(1, $eventCounter->logout);
		Assert::true($manager->isUserLoggedIn());
		Assert::same($activeIdentity, $manager->getIdentity());
		Assert::same(self::DO_NOT_STAY_SIGNED_IN_TIME, $userStorage->getExpiration());
	}

	public function testLogout(): void
	{
		$eventCounter = (object) [
			'login' => 0,
			'logout' => 0,
		];
		$userStorage = new UserStorage();
		$manager = $this->createManager($userStorage, $eventCounter);

		$activeIdentity = new Identity(self::USER_NAME, self::USER_PASSWORD);
		$authenticator = new Authenticator(
			[
				$activeIdentity,
			]
		);

		$manager->logout();
		Assert::same(0, $eventCounter->logout);

		$manager->login($authenticator, new Credentials(self::USER_NAME, self::USER_PASSWORD), '', false);
		$manager->logout();
		Assert::false($manager->isUserLoggedIn());
		Assert::same(1, $eventCounter->logout);
		Assert::same($activeIdentity, $manager->getIdentity());

		$manager->login($authenticator, new Credentials(self::USER_NAME, self::USER_PASSWORD), '', false);
		$manager->logout(true);
		Assert::false($manager->isUserLoggedIn());
		Assert::same(2, $eventCounter->logout);
		Assert::null($manager->getIdentity());
	}

	/**
	 * @param \GrandMediaTests\Security\Authentication\Mocks\UserStorage $userStorage
	 * @param object $eventCounter
	 */
	private function createManager(UserStorage $userStorage, $eventCounter): AuthenticationManager
	{
		$manager = new AuthenticationManager($userStorage);

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
