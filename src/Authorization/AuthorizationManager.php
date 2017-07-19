<?php declare(strict_types = 1);

namespace GrandMedia\Security\Authorization;

use GrandMedia\Security\Authentication\AuthenticationManager;
use GrandMedia\Security\Authentication\Identity;

final class AuthorizationManager
{
	/** @var AuthenticationManager */
	private $authenticationManager;

	/** @var IAuthorizator[] */
	private $authorizators = [];

	public function __construct(AuthenticationManager $authenticationManager)
	{
		$this->authenticationManager = $authenticationManager;
	}

	public function isAllowed(string $resource, string $privilege): bool
	{
		return $this->isUserAllowed($this->authenticationManager->getIdentity(), $resource, $privilege);
	}

	public function isUserAllowed(?Identity $identity, string $resource, string $privilege): bool
	{
		$allowed = null;

		foreach ($this->authorizators as $authorizator) {
			if ($authorizator->supportsResource($resource)) {
				$allowed = (is_bool($allowed) ? $allowed : true) && $authorizator->isAllowed(
						$identity,
						$resource,
						$privilege
					);
			}
		}

		if (is_bool($allowed)) {
			return $allowed;
		}

		throw new ResourceNotFoundException($resource);
	}

	public function addAuthorizator(IAuthorizator $authorizator)
	{
		$this->authorizators[] = $authorizator;
	}
}
