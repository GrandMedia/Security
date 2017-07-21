<?php declare(strict_types = 1);

namespace GrandMedia\Security\Authentication;

use Nette\Security\AuthenticationException;
use Nette\Security\IUserStorage;
use Nette\SmartObject;

/**
 * @method onLoggedIn(Identity $identity)
 * @method onLoggedOut(?Identity $identity)
 */
final class AuthenticationManager
{
	use SmartObject;

	/** @var callable[] */
	public $onLoggedIn;

	/** @var callable[] */
	public $onLoggedOut;

	/** @var IUserStorage */
	private $userStorage;

	public function __construct(IUserStorage $userStorage)
	{
		$this->userStorage = $userStorage;
	}

	public function login(
		IAuthenticator $authenticator,
		ICredentials $credentials,
		string $expirationTime,
		bool $clearIdentityAfterExpiration
	): void {
		$this->logout(true);

		$identity = $authenticator->authenticate($credentials);

		if (!$identity->isActive()) {
			throw new AuthenticationException('', IAuthenticator::NOT_APPROVED);
		}

		$this->userStorage->setExpiration(
			$expirationTime,
			$clearIdentityAfterExpiration ? IUserStorage::CLEAR_IDENTITY : 0
		);
		$this->userStorage->setIdentity($identity);
		$this->userStorage->setAuthenticated(true);
		$this->onLoggedIn($identity);
	}

	public function logout($clearIdentity = false): void
	{
		if ($this->userStorage->isAuthenticated()) {
			$this->onLoggedOut($this->getIdentity());
			$this->userStorage->setAuthenticated(false);
		}

		if ($clearIdentity) {
			$this->userStorage->setIdentity(null);
		}
	}

	public function getUserStorage(): IUserStorage
	{
		return $this->userStorage;
	}

	public function isUserLoggedIn(): bool
	{
		return $this->userStorage->isAuthenticated();
	}

	public function getIdentity(): ?Identity
	{
		$identity = $this->userStorage->getIdentity();
		return $identity instanceof Identity ? $identity : null;
	}

	public function getLogoutReason(): ?int
	{
		return $this->userStorage->getLogoutReason();
	}
}
