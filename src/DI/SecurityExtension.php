<?php declare(strict_types = 1);

namespace GrandMedia\Security\DI;

use GrandMedia\Security\Authentication\AuthenticationManager;
use GrandMedia\Security\Authorization\AuthorizationManager;
use GrandMedia\Security\Authorization\Authorizator;

final class SecurityExtension extends \Nette\DI\CompilerExtension
{

	public function loadConfiguration(): void
	{
		$containerBuilder = $this->getContainerBuilder();

		$containerBuilder->addDefinition($this->prefix('authenticationManager'))
			->setClass(AuthenticationManager::class);

		$containerBuilder->addDefinition($this->prefix('authorizationManager'))
			->setClass(AuthorizationManager::class);
	}

	public function beforeCompile(): void
	{
		$containerBuilder = $this->getContainerBuilder();

		$manager = $containerBuilder->getDefinition($this->prefix('authorizationManager'));
		foreach ($containerBuilder->findByType(Authorizator::class) as $authorizator => $definition) {
			$manager->addSetup('addAuthorizator', [\sprintf('@%s', $authorizator)]);
		}
	}

}
