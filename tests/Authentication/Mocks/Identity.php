<?php declare(strict_types = 1);

namespace GrandMediaTests\Security\Authentication\Mocks;

final class Identity implements \Nette\Security\IIdentity
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

	public function verify(string $password): bool
	{
		return $this->password === $password;
	}

	public function getId(): string
	{
		return $this->name;
	}

	public function getName(): string
	{
		return $this->name;
	}

	public function getRoles(): array
	{
		return [
			$this->name,
		];
	}

}
