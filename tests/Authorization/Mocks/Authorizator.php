<?php declare(strict_types = 1);

namespace GrandMediaTests\Security\Authorization\Mocks;

use Nette\Security\IIdentity;

final class Authorizator implements \GrandMedia\Security\Authorization\IAuthorizator
{

	/** @var bool[][][] */
	private $resources;

	/**
	 * @param bool[][][] $resources
	 */
	public function __construct(array $resources)
	{
		$this->resources = $resources;
	}

	public function isAllowed(?IIdentity $identity, string $resource, string $privilege): bool
	{
		if ($identity && isset($this->resources[$identity->getId()]) &&
			isset($this->resources[$identity->getId()][$resource]) &&
			isset($this->resources[$identity->getId()][$resource][$privilege])
		) {
			return $this->resources[$identity->getId()][$resource][$privilege];
		}

		return false;
	}

	public function supportsResource(string $resource): bool
	{
		if (count($this->resources) === 0) {
			return false;
		}

		$supports = true;

		foreach ($this->resources as $identityResources) {
			$supports = $supports && isset($identityResources[$resource]);
		}

		return $supports;
	}

}
