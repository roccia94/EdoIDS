<?php
declare(strict_types=1);

namespace Edoardo\Ids\Model\Detector;

use Edoardo\Ids\Model\Detector\Phpids\GetConfig;
use Edoardo\Ids\Model\DetectorInterface;
use Edoardo\Ids\Model\SecurityThreat;
use Edoardo\Ids\Model\SecurityThreatFactory;
use Exception;
use IDS\Init;
use IDS\Monitor;
use Magento\Framework\Exception\LocalizedException;

class Phpids implements DetectorInterface
{
    /**
     * @var Monitor
     */
    private $idsMonitor;

    /**
     * @var GetConfig
     */
    private $getConfig;

    /**
     * @var SecurityThreatFactory
     */
    private $securityThreatFactory;

    /**
     * @param GetConfig $getConfig
     * @param SecurityThreatFactory $securityThreatFactory
     */
    public function __construct(
        GetConfig $getConfig,
        SecurityThreatFactory $securityThreatFactory
    ) {
        $this->securityThreatFactory = $securityThreatFactory;
        $this->getConfig = $getConfig;
    }

    /**
     * @throws Exception
     */
    private function initialize(): void
    {
        if ($this->idsMonitor === null) {
            $init = new Init($this->getConfig->execute());
            $this->idsMonitor = new Monitor($init);
        }
    }

    /**
     * Scan request
     *
     * @param array $requestPayload
     * @return SecurityThreat
     * @throws LocalizedException
     */
    public function execute(array $requestPayload): SecurityThreat
    {
        try {
            $this->initialize();
        } catch (Exception $e) {
            throw new LocalizedException(__('Unable to initialize IDS'));
        }

        $result = $this->idsMonitor->run($requestPayload);

        return $this->securityThreatFactory->create([
            'impact' => (int) $result->getImpact(),
            'tags' => $result->getTags()
        ]);
    }
}
