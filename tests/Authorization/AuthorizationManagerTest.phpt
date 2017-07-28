<?php declare(strict_types = 1);

namespace GrandMediaTests\Security\Authorization;

use GrandMedia\Security\Authentication\AuthenticationManager;
use GrandMedia\Security\Authorization\AuthorizationManager;
use GrandMedia\Security\Authorization\ResourceNotFoundException;
use GrandMediaTests\Security\Authentication\Mocks\UserStorage;
use GrandMediaTests\Security\Authorization\Mocks\Authorizator;
use Tester\Assert;

require_once __DIR__ . '/../bootstrap.php';

/**
 * @testCase
 */
final class AuthorizationManagerTest extends \Tester\TestCase
{

	private const SUPPORTED_RESOURCE = 'foo';
	private const SUPPORTED_PRIVILEGE = 'bar';
	private const UNSUPPORTED_RESOURCE = 'baz';

	public function testIsAllowed(): void
	{
		$manager = new AuthorizationManager(new AuthenticationManager(new UserStorage()));
		$resourcesWithTrue = [
			self::SUPPORTED_RESOURCE => [
				self::SUPPORTED_PRIVILEGE => true,
			],
		];
		$resourcesWithFalse = [
			self::SUPPORTED_RESOURCE => [
				self::SUPPORTED_PRIVILEGE => false,
			],
		];

		Assert::exception(
			function () use ($manager) {
				$manager->isAllowed(self::SUPPORTED_PRIVILEGE, self::SUPPORTED_PRIVILEGE);
			},
			ResourceNotFoundException::class
		);

		$manager->addAuthorizator(new Authorizator($resourcesWithTrue));
		Assert::true($manager->isAllowed(self::SUPPORTED_RESOURCE, self::SUPPORTED_PRIVILEGE));
		Assert::exception(
			function () use ($manager) {
				$manager->isAllowed(self::UNSUPPORTED_RESOURCE, self::SUPPORTED_PRIVILEGE);
			},
			ResourceNotFoundException::class
		);

		$manager->addAuthorizator(new Authorizator($resourcesWithFalse));
		Assert::false($manager->isAllowed(self::SUPPORTED_RESOURCE, self::SUPPORTED_PRIVILEGE));
	}

}

(new AuthorizationManagerTest())->run();
