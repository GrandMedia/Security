<?php declare(strict_types = 1);

namespace GrandMedia\Security\Authorization;

final class ResourceNotFoundException extends \InvalidArgumentException
{

	public function __construct(string $resource)
	{
		parent::__construct(\sprintf('Resource %s not found.', $resource));
	}

}
