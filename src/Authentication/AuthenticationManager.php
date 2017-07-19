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

	/** @var string */
	private $staySignedInTime;

	/** @var string */
	private $doNotStaySignedInTime;

	public function __construct(IUserStorage $userStorage, string $staySignedInTime, string $doNotStaySignedInTime)
	{
		$this->userStorage = $userStorage;
		$this->staySignedInTime = $staySignedInTime;
		$this->doNotStaySignedInTime = $doNotStaySignedInTime;
	}

	public function login(IAuthenticator $authenticator, ICredentials $credentials, bool $staySignedIn): void
	{
		$this->logout(true);

		$identity = $authenticator->authenticate($credentials);

		if (!$identity->isActive()) {
			throw new AuthenticationException('', IAuthenticator::NOT_APPROVED);
		}

		if ($staySignedIn) {
			$this->userStorage->setExpiration($this->staySignedInTime, false);
		} else {
			$this->userStorage->setExpiration($this->doNotStaySignedInTime, true);
		}

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
