<?php declare(strict_types = 1);

namespace GrandMedia\Security\Authentication;

use Nette\Security\IIdentity;
use Nette\Security\IUserStorage;

/**
 * @method onLoggedIn(IIdentity $identity)
 * @method onLoggedOut(?IIdentity $identity)
 */
final class AuthenticationManager
{

	use \Nette\SmartObject;

	/** @var callable[] */
	public $onLoggedIn;

	/** @var callable[] */
	public $onLoggedOut;

	/** @var \Nette\Security\IUserStorage */
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
	): void
	{
		$this->logout(true);

		$identity = $authenticator->authenticate($credentials);

		$this->userStorage->setExpiration(
			$expirationTime,
			$clearIdentityAfterExpiration ? IUserStorage::CLEAR_IDENTITY : 0
		);
		$this->userStorage->setIdentity($identity);
		$this->userStorage->setAuthenticated(true);
		$this->onLoggedIn($identity);
	}

	public function logout(bool $clearIdentity = false): void
	{
		if ($this->userStorage->isAuthenticated()) {
			$this->onLoggedOut($this->getIdentity());
			$this->userStorage->setAuthenticated(false);
		}

		if ($clearIdentity) {
			$this->userStorage->setIdentity(null);
		}
	}

	public function isUserLoggedIn(): bool
	{
		return $this->userStorage->isAuthenticated();
	}

	public function getIdentity(): ?IIdentity
	{
		$identity = $this->userStorage->getIdentity();
		return $identity instanceof IIdentity ? $identity : null;
	}

	public function getLogoutReason(): ?int
	{
		return $this->userStorage->getLogoutReason();
	}

}
