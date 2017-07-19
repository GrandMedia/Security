<?php declare(strict_types = 1);

namespace GrandMediaTests\Security\Authorization\Mocks;

use GrandMedia\Security\Authentication\Identity;
use GrandMedia\Security\Authorization\IAuthorizator;

final class Authorizator implements IAuthorizator
{
	/** @var array */
	private $resources;

	/**
	 * @param array $resources
	 */
	public function __construct(array $resources)
	{
		$this->resources = $resources;
	}

	public function isAllowed(?Identity $identity, string $resource, string $privilege): bool
	{
		if (isset($this->resources[$resource])) {
			if (isset($this->resources[$resource][$privilege])) {
				return $this->resources[$resource][$privilege];
			}
		}

		return false;
	}

	public function supportsResource(string $resource): bool
	{
		return isset($this->resources[$resource]);
	}
}
