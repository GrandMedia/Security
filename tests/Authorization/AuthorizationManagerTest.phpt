<?php declare(strict_types = 1);

namespace GrandMediaTests\Security\Authorization;

use GrandMedia\Security\Authentication\AuthenticationManager;
use GrandMedia\Security\Authorization\AuthorizationManager;
use GrandMediaTests\Security\Authentication\Mocks\IdentityMock;
use GrandMediaTests\Security\Authentication\Mocks\UserStorageMock;
use GrandMediaTests\Security\Authorization\Mocks\AuthorizatorMock;
use Tester\Assert;

require_once __DIR__ . '/../bootstrap.php';

/**
 * @testCase
 */
final class AuthorizationManagerTest extends \Tester\TestCase
{

	private const SUPPORTED_RESOURCE = 'foo';
	private const UNSUPPORTED_RESOURCE = 'baz';
	private const ALLOWED_PRIVILEGE = 'bar';
	private const DENY_PRIVILEGE = 'baz';

	private const IDENTITY_ID = '1';

	public function testIsAllowed(): void
	{
		$manager = $this->createManager();

		Assert::true($manager->isAllowed(self::SUPPORTED_RESOURCE, self::ALLOWED_PRIVILEGE));
		Assert::false($manager->isAllowed(self::SUPPORTED_RESOURCE, self::DENY_PRIVILEGE));
	}

	/**
	 * @throws \GrandMedia\Security\Authorization\ResourceNotFoundException
	 */
	public function testIsAllowedUnsupportedResource(): void
	{
		$manager = $this->createManager();

		$manager->isAllowed(self::UNSUPPORTED_RESOURCE, self::ALLOWED_PRIVILEGE);
	}

	public function testIsUserAllowed(): void
	{
		$identity = new IdentityMock(self::IDENTITY_ID, '');
		$manager = $this->createManager();

		Assert::true($manager->isUserAllowed($identity, self::SUPPORTED_RESOURCE, self::ALLOWED_PRIVILEGE));
		Assert::false($manager->isUserAllowed($identity, self::SUPPORTED_RESOURCE, self::DENY_PRIVILEGE));

		Assert::false($manager->isUserAllowed(null, self::SUPPORTED_RESOURCE, self::ALLOWED_PRIVILEGE));

		$resources = [
			self::IDENTITY_ID => [
				self::SUPPORTED_RESOURCE => [
					self::ALLOWED_PRIVILEGE => false,
					self::DENY_PRIVILEGE => false,
				],
			],
		];
		$manager->addAuthorizator(new AuthorizatorMock($resources));
		Assert::false($manager->isUserAllowed($identity, self::SUPPORTED_RESOURCE, self::ALLOWED_PRIVILEGE));
	}

	/**
	 * @throws \GrandMedia\Security\Authorization\ResourceNotFoundException
	 */
	public function testIsUserAllowedUnsupportedResource(): void
	{
		$manager = $this->createManager();

		$manager->isUserAllowed(null, self::UNSUPPORTED_RESOURCE, self::ALLOWED_PRIVILEGE);
	}

	private function createManager(): AuthorizationManager
	{
		$identity = new IdentityMock(self::IDENTITY_ID, '');
		$userStorage = new UserStorageMock();
		$userStorage->setAuthenticated(true);
		$userStorage->setIdentity($identity);

		$manager = new AuthorizationManager(new AuthenticationManager($userStorage));
		$resources = [
			self::IDENTITY_ID => [
				self::SUPPORTED_RESOURCE => [
					self::ALLOWED_PRIVILEGE => true,
					self::DENY_PRIVILEGE => false,
				],
			],
		];
		$manager->addAuthorizator(new AuthorizatorMock($resources));

		return $manager;
	}

}

(new AuthorizationManagerTest())->run();
