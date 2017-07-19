<?php declare(strict_types = 1);

namespace GrandMediaTests\Security\Authentication\Mocks;

use GrandMedia\Security\Authentication\ICredentials;

final class Credentials implements ICredentials
{
	/** @var string */
	private $name;

	/** @var string */
	private $password;

	public function __construct(string $name, string $password)
	{
		$this->name = $name;
		$this->password = $password;
	}

	public function getName(): string
	{
		return $this->name;
	}

	public function getPassword(): string
	{
		return $this->password;
	}
}
