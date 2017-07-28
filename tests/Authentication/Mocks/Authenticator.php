<?php declare(strict_types = 1);

namespace GrandMediaTests\Security\Authentication\Mocks;

use GrandMedia\Security\Authentication\ICredentials;
use Nette\Security\AuthenticationException;
use Nette\Security\IIdentity;

final class Authenticator implements \GrandMedia\Security\Authentication\IAuthenticator
{

	/** @var \GrandMediaTests\Security\Authentication\Mocks\Identity[] */
	private $identities;

	/**
	 * @param \GrandMediaTests\Security\Authentication\Mocks\Identity[] $identities
	 */
	public function __construct(array $identities)
	{
		$this->identities = $identities;
	}

	public function authenticate(ICredentials $credentials): IIdentity
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
