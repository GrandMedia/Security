<?php declare(strict_types = 1);

namespace GrandMedia\Security\Authentication;

use Doctrine\ORM\Mapping as ORM;
use Nette\Security\IIdentity;
use Nette\Security\Passwords;

/**
 * @ORM\MappedSuperclass
 */
abstract class Identity implements IIdentity
{
	/**
	 * @ORM\Column(type="string")
	 * @var string
	 */
	private $password;

	/**
	 * @ORM\Column(type="string")
	 * @var string
	 */
	private $role;

	/**
	 * @ORM\Column(type="boolean")
	 * @var bool
	 */
	private $active = true;

	/** @var bool */
	private $passwordChanged = false;

	public function __construct(string $password, string $role = '')
	{
		$this->password = Passwords::hash($password);
		$this->role = $role;
	}

	public function verify(string $password): bool
	{
		return Passwords::verify($password, $this->password);
	}

	public function changePassword(string $password)
	{
		$this->password = Passwords::hash($password);
		$this->passwordChanged = true;
	}

	public function rehashPassword()
	{
		$this->password = Passwords::hash($this->password);
	}

	public function activate()
	{
		$this->active = true;
	}

	public function deactivate()
	{
		$this->active = false;
	}

	public function isPasswordChanged(): bool
	{
		return $this->passwordChanged;
	}

	public function isActive(): bool
	{
		return $this->active;
	}

	public function getRoles(): array
	{
		if ($this->role === '') {
			return [];
		}

		return [$this->role];
	}

	abstract public function getName(): string;
}
