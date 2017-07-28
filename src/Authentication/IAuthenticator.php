<?php declare(strict_types = 1);

namespace GrandMedia\Security\Authentication;

use Nette\Security\IIdentity;

interface IAuthenticator
{

	public const IDENTITY_NOT_FOUND = 1;
	public const INVALID_CREDENTIAL = 2;
	public const FAILURE = 3;
	public const NOT_APPROVED = 4;

	public function authenticate(ICredentials $credentials): IIdentity;

}
