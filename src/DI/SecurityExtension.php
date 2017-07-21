<?php declare(strict_types = 1);

namespace GrandMedia\Security\DI;

use GrandMedia\Security\Authentication\AuthenticationManager;
use GrandMedia\Security\Authentication\AutomaticLogoutListener;
use GrandMedia\Security\Authorization\AuthorizationManager;
use GrandMedia\Security\Authorization\IAuthorizator;
use Kdyby\Doctrine\DI\IEntityProvider;
use Kdyby\Events\DI\EventsExtension;
use Nette\DI\CompilerExtension;

final class SecurityExtension extends CompilerExtension implements IEntityProvider
{
	public function loadConfiguration()
	{
		$containerBuilder = $this->getContainerBuilder();

		$containerBuilder->addDefinition($this->prefix('authenticationManager'))
			->setClass(AuthenticationManager::class);

		$containerBuilder->addDefinition($this->prefix('automaticLogoutListener'))
			->setClass(AutomaticLogoutListener::class)
			->addTag(EventsExtension::TAG_SUBSCRIBER);

		$containerBuilder->addDefinition($this->prefix('authorizationManager'))
			->setClass(AuthorizationManager::class);
	}

	public function beforeCompile()
	{
		$containerBuilder = $this->getContainerBuilder();

		$manager = $containerBuilder->getDefinition($this->prefix('authorizationManager'));
		foreach ($containerBuilder->findByType(IAuthorizator::class) as $authorizator => $definition) {
			$manager->addSetup('addAuthorizator', ["@$authorizator"]);
		}
	}

	public function getEntityMappings(): array
	{
		return [
			'GrandMedia\Security\Authentication' => __DIR__ . '/../Authentication',
		];
	}
}
