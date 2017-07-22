<?php declare(strict_types = 1);

namespace GrandMedia\Security\Authentication;

use Nette\Security\IIdentity;

interface IAuthenticator
{
	const IDENTITY_NOT_FOUND = 1;
	const INVALID_CREDENTIAL = 2;
	const FAILURE = 3;
	const NOT_APPROVED = 4;

	public function authenticate(ICredentials $credentials): IIdentity;
}
