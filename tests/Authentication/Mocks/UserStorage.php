<?php declare(strict_types = 1);

namespace GrandMediaTests\Security\Authentication\Mocks;

use Nette\Security\IIdentity;
use Nette\Security\IUserStorage;

final class UserStorage implements IUserStorage
{
	/** @var bool */
	private $auth = false;

	/** @var IIdentity|null */
	private $identity;

	/** @var string */
	private $expiration;

	public function setAuthenticated($state): void
	{
		$this->auth = $state;
	}

	public function isAuthenticated(): bool
	{
		return $this->auth;
	}

	public function getIdentity(): ?IIdentity
	{
		return $this->identity;
	}

	public function setIdentity(IIdentity $identity = null): void
	{
		$this->identity = $identity;
	}

	public function getExpiration(): string
	{
		return $this->expiration;
	}

	public function setExpiration($time, $flags = 0): void
	{
		$this->expiration = $time;
	}

	public function getLogoutReason(): ?int
	{
		return null;
	}
}
