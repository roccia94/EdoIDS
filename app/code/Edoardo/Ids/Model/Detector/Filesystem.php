<?php
declare(strict_types=1);

namespace Edoardo\Ids\Model\Detector;

use Edoardo\Ids\Model\DetectorInterface;
use Edoardo\Ids\Model\GetMatchesCount;
use Edoardo\Ids\Model\SecurityThreat;
use Edoardo\Ids\Model\SecurityThreatFactory;
use Edoardo\Ids\Model\Tags;

class Filesystem implements DetectorInterface
{
    private const SUSPICIOUS_MULTIPLIER = 10;
    private const CRITICAL_MULTIPLIER = 40;

    /**
     * @var SecurityThreatFactory
     */
    private $securityThreatFactory;

    /**
     * @var GetMatchesCount
     */
    private $getMatchesCount;

    /**
     * @param GetMatchesCount $getMatchesCount
     * @param SecurityThreatFactory $securityThreatFactory
     */
    public function __construct(
        GetMatchesCount $getMatchesCount,
        SecurityThreatFactory $securityThreatFactory
    ) {
        $this->securityThreatFactory = $securityThreatFactory;
        $this->getMatchesCount = $getMatchesCount;
    }

    /**
     * @return array
     */
    private function getSuspiciousSearchPatterns(): array
    {
        return [
            '/\\.\\./'
        ];
    }

    /**
     * @return array
     */
    private function getCriticalSearchPatterns(): array
    {
        return [
            '/\\.\\//',
            '/\\/etc\\//',
            '/\\/tmp\\//',
            '/\\/var\\//',
        ];
    }

    /**
     * @inheritDoc
     */
    public function execute(array $requestPayload): SecurityThreat
    {
        $suspiciousScore = 0;
        $criticalScore = 0;

        foreach ($requestPayload as $type => $data) {
            foreach ($data as $field => $value) {
                $suspiciousScore += $this->getMatchesCount->execute($value, $this->getSuspiciousSearchPatterns());
                $criticalScore += $this->getMatchesCount->execute($value, $this->getCriticalSearchPatterns());
            }
        }

        $finalScore = $suspiciousScore * self::SUSPICIOUS_MULTIPLIER + $criticalScore * self::CRITICAL_MULTIPLIER;

        return $this->securityThreatFactory->create([
            'impact' => $finalScore,
            'tags' => $finalScore > 0 ? [Tags::LFE] : []
        ]);
    }
}
