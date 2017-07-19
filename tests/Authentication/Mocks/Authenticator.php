<?php declare(strict_types = 1);

namespace GrandMediaTests\Security\Authentication\Mocks;

use GrandMedia\Security\Authentication\IAuthenticator;
use GrandMedia\Security\Authentication\ICredentials;
use GrandMedia\Security\Authentication\Identity;
use Nette\Security\AuthenticationException;

final class Authenticator implements IAuthenticator
{
	/** @var Identity[] */
	private $identities;

	public function __construct(array $identities)
	{
		$this->identities = $identities;
	}

	public function authenticate(ICredentials $credentials): Identity
	{
		if ($credentials instanceof Credentials) {
			foreach ($this->identities as $identity) {
				if ($identity->getName() === $credentials->getName()) {
					if ($identity->verify($credentials->getPassword())) {
						return $identity;
					} else {
						throw new AuthenticationException('', self::INVALID_CREDENTIAL);
					}
				}
			}
		}

		throw new AuthenticationException('', self::IDENTITY_NOT_FOUND);
	}
}
