<?php declare(strict_types = 1);

namespace GrandMediaTests\Security\DI;

use GrandMedia\Security\Authentication\AuthenticationManager;
use GrandMedia\Security\Authorization\AuthorizationManager;
use GrandMediaTests\Security\Authorization\Mocks\Authorizator;
use Nette\Configurator;
use Nette\DI\Container;
use Tester\Assert;

require_once __DIR__ . '/../bootstrap.php';

/**
 * @testCase
 */
final class SecurityExtensionTest extends \Tester\TestCase
{

	public function testFunctionality(): void
	{
		$container = $this->createContainer(null);

		$authenticationManager = $container->getByType(AuthenticationManager::class);
		Assert::true($authenticationManager instanceof AuthenticationManager);

		$authorizationManager = $container->getByType(AuthorizationManager::class);
		Assert::true($authorizationManager instanceof AuthorizationManager);
	}

	public function testAddAuthorizator(): void
	{
		$container = $this->createContainer('add-authorizator');

		/** @var \GrandMedia\Security\Authorization\AuthorizationManager $authorizationManager */
		$authorizationManager = $container->getByType(AuthorizationManager::class);
		foreach ($authorizationManager->getAuthorizators() as $authorizator) {
			Assert::true($authorizator instanceof Authorizator);
		}
	}

	private function createContainer(?string $configFile): Container
	{
		$config = new Configurator();

		$config->setTempDirectory(TEMP_DIR);
		$config->addConfig(__DIR__ . '/config/reset.neon');
		if ($configFile !== null) {
			$config->addConfig(__DIR__ . \sprintf('/config/%s.neon', $configFile));
		}

		return $config->createContainer();
	}

}

(new SecurityExtensionTest())->run();
