<?php declare(strict_types = 1);

namespace GrandMediaTests\Security\Authentication\Mocks;

final class Identity extends \GrandMedia\Security\Authentication\Identity
{
	/** @var string */
	private $name;

	public function __construct(string $name, string $password, string $role = '')
	{
		$this->name = $name;

		parent::__construct($password, $role);
	}


	public function getId(): string
	{
		return $this->name;
	}

	public function getName(): string
	{
		return $this->name;
	}
}
