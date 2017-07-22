<?php declare(strict_types = 1);

namespace GrandMedia\Security\DI;

use GrandMedia\Security\Authentication\AuthenticationManager;
use GrandMedia\Security\Authorization\AuthorizationManager;
use GrandMedia\Security\Authorization\IAuthorizator;
use Nette\DI\CompilerExtension;

final class SecurityExtension extends CompilerExtension
{
	public function loadConfiguration()
	{
		$containerBuilder = $this->getContainerBuilder();

		$containerBuilder->addDefinition($this->prefix('authenticationManager'))
			->setClass(AuthenticationManager::class);

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
}
