<?php declare(strict_types = 1);

namespace GrandMediaTests\Security\Authentication\Mocks;

use Nette\Security\IIdentity;

final class UserStorage implements \Nette\Security\IUserStorage
{

	/** @var bool */
	private $auth = false;

	/** @var \Nette\Security\IIdentity|null */
	private $identity;

	/** @var string */
	private $expiration;

	/**
	 * @phpcsSuppress SlevomatCodingStandard.TypeHints.TypeHintDeclaration.MissingParameterTypeHint
	 * @param bool $state
	 */
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

	public function setIdentity(?IIdentity $identity = null): void
	{
		$this->identity = $identity;
	}

	public function getExpiration(): string
	{
		return $this->expiration;
	}

	/**
	 * @phpcsSuppress SlevomatCodingStandard.TypeHints.TypeHintDeclaration.MissingParameterTypeHint
	 * @param string $time
	 * @param int $flags
	 */
	public function setExpiration($time, $flags = 0): void
	{
		$this->expiration = $time;
	}

	public function getLogoutReason(): ?int
	{
		return null;
	}

}
