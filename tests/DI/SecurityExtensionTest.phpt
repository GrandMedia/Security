<?php declare(strict_types = 1);

namespace GrandMediaTests\Security\DI;

use GrandMedia\Security\Authentication\AuthenticationManager;
use GrandMedia\Security\Authorization\AuthorizationManager;
use GrandMediaTests\Security\Authorization\Mocks\Authorizator;
use Nette\Configurator;
use Nette\DI\Container;
use Tester\Assert;
use Tester\TestCase;

require_once __DIR__ . '/../bootstrap.php';

final class SecurityExtensionTest extends TestCase
{
	public function testFunctionality()
	{
		$container = $this->createContainer(null);

		$authenticationManager = $container->getByType(AuthenticationManager::class);
		Assert::true($authenticationManager instanceof AuthenticationManager);

		$authorizationManager = $container->getByType(AuthorizationManager::class);
		Assert::true($authorizationManager instanceof AuthorizationManager);
	}

	public function testAddAuthorizator()
	{
		$container = $this->createContainer('add-authorizator');

		/** @var AuthorizationManager $authorizationManager */
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
			$config->addConfig(__DIR__ . "/config/$configFile.neon");
		}

		return $config->createContainer();
	}
}

(new SecurityExtensionTest())->run();
