<?php
declare(strict_types=1);

namespace Edoardo\Ids\Model;

use Edoardo\Ids\Exception\IdsException;
use Magento\Framework\Exception\LocalizedException;

class CheckRequest
{
    /**
     * @var Config
     */
    private $config;

    /**
     * @var DetectorInterface
     */
    private $detector;

    /**
     * @var LogSecurityThreat
     */
    private $logSecurityIssue;

    /**
     * @var IsAdminPath
     */
    private $isAdminPath;

    /**
     * @var GetRequestPayload
     */
    private $getRequestPayload;

    /**
     * @param Config $config
     * @param GetRequestPayload $getRequestPayload
     * @param LogSecurityThreat $logSecurityIssue
     * @param IsAdminPath $isAdminPath
     * @param DetectorInterface $detector
     */
    public function __construct(
        Config $config,
        GetRequestPayload $getRequestPayload,
        LogSecurityThreat $logSecurityIssue,
        IsAdminPath $isAdminPath,
        DetectorInterface $detector
    ) {
        $this->config = $config;
        $this->detector = $detector;
        $this->logSecurityIssue = $logSecurityIssue;
        $this->isAdminPath = $isAdminPath;
        $this->getRequestPayload = $getRequestPayload;
    }

    /**
     * @param SecurityThreat $securityThreat
     */
    private function logReport(SecurityThreat $securityThreat): void
    {
        $this->logSecurityIssue->execute($securityThreat);
    }

    /**
     * Check request and throw an exception if a security impact is detected
     *
     * @throws IdsException
     * @throws LocalizedException
     */
    public function execute(): void
    {
        if (!$this->isAdminPath->execute()) {
            $securityThreat = $this->detector->execute($this->getRequestPayload->execute());

            if ($securityThreat->getImpact() >= $this->config->getMinScoreToLog()) {
                $this->logReport($securityThreat);
            }

            if ($securityThreat->getImpact() >= $this->config->getMinScoreToStop()) {
                throw new IdsException(__('Security exception'));
            }
        }
    }
}
