<?php declare(strict_types = 1);

namespace GrandMedia\Security\Authentication;

use Doctrine\ORM\EntityNotFoundException;
use Kdyby\Events\Subscriber;

final class AutomaticLogoutListener implements Subscriber
{
	/** @var AuthenticationManager */
	private $authenticationManager;

	public function __construct(AuthenticationManager $authenticationManager)
	{
		$this->authenticationManager = $authenticationManager;
	}

	public function check()
	{
		try {
			/** @var Identity $identity */
			$identity = $this->authenticationManager->getIdentity();
			if ($identity instanceof Identity && !$identity->isActive()) {
				$this->authenticationManager->logout();
			}
		} catch (EntityNotFoundException $ex) {
			$this->authenticationManager->logout(true);
		}
	}

	public function getSubscribedEvents(): array
	{
		return [
			'Nette\Application\Application::onStartup' => 'check'
		];
	}
}
