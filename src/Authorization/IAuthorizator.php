<?php declare(strict_types = 1);

namespace GrandMedia\Security\Authorization;

use Nette\Security\IIdentity;

interface IAuthorizator
{

	public function isAllowed(?IIdentity $identity, string $resource, string $privilege): bool;

	public function supportsResource(string $resource): bool;

}
