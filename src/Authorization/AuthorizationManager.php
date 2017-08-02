<?php declare(strict_types = 1);

namespace GrandMedia\Security\Authorization;

use GrandMedia\Security\Authentication\AuthenticationManager;
use Nette\Security\IIdentity;

final class AuthorizationManager
{

	/** @var \GrandMedia\Security\Authentication\AuthenticationManager */
	private $authenticationManager;

	/** @var \GrandMedia\Security\Authorization\Authorizator[] */
	private $authorizators = [];

	public function __construct(AuthenticationManager $authenticationManager)
	{
		$this->authenticationManager = $authenticationManager;
	}

	public function isAllowed(string $resource, string $privilege): bool
	{
		return $this->isUserAllowed($this->authenticationManager->getIdentity(), $resource, $privilege);
	}

	public function isUserAllowed(?IIdentity $identity, string $resource, string $privilege): bool
	{
		$allowed = null;

		foreach ($this->authorizators as $authorizator) {
			if ($authorizator->supportsResource($resource)) {
				$allowed = (\is_bool($allowed) ? $allowed : true) && $authorizator->isAllowed(
					$identity,
					$resource,
					$privilege
				);
			}
		}

		if (\is_bool($allowed)) {
			return $allowed;
		}

		throw new ResourceNotFoundException($resource);
	}

	public function addAuthorizator(Authorizator $authorizator): void
	{
		$this->authorizators[] = $authorizator;
	}

	/**
	 * @return \GrandMedia\Security\Authorization\Authorizator[]
	 */
	public function getAuthorizators(): array
	{
		return $this->authorizators;
	}

}
