<?php declare(strict_types = 1);

namespace GrandMedia\Security\Authorization;

use GrandMedia\Security\Authentication\Identity;

interface IAuthorizator
{
	public function isAllowed(?Identity $identity, string $resource, string $privilege): bool;

	public function supportsResource(string $resource): bool;
}
