<?php declare(strict_types = 1);

namespace GrandMediaTests\Security\Authentication\Mocks;

use GrandMedia\Security\Authentication\Credentials;
use Nette\Security\AuthenticationException;
use Nette\Security\IIdentity;

final class AuthenticatorMock implements \GrandMedia\Security\Authentication\Authenticator
{

	/** @var \GrandMediaTests\Security\Authentication\Mocks\IdentityMock[] */
	private $identities;

	/**
	 * @param \GrandMediaTests\Security\Authentication\Mocks\IdentityMock[] $identities
	 */
	public function __construct(array $identities)
	{
		$this->identities = $identities;
	}

	public function authenticate(Credentials $credentials): IIdentity
	{
		if ($credentials instanceof CredentialsMock) {
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
