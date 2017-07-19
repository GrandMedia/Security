<?php declare(strict_types = 1);

namespace GrandMediaTests\Security\Authentication;

use GrandMediaTests\Security\Authentication\Mocks\Identity;
use Tester\Assert;
use Tester\TestCase;

require_once __DIR__ . '/../bootstrap.php';

final class IdentityTest extends TestCase
{
	public function testVerify()
	{
		$identity = new Identity('foo', 'foo');

		Assert::true($identity->verify('foo'));
	}

	public function testChangePassword()
	{
		$identity = new Identity('foo', 'foo');
		$identity->changePassword('bar');

		Assert::true($identity->verify('bar'));
	}
}

(new IdentityTest())->run();
