<?php
declare(strict_types=1);

namespace Edoardo\Ids\Model\Detector;

use Edoardo\Ids\Model\DetectorInterface;
use Edoardo\Ids\Model\GetMatchesCount;
use Edoardo\Ids\Model\SecurityThreat;
use Edoardo\Ids\Model\SecurityThreatFactory;
use Edoardo\Ids\Model\Tags;

class Sqli implements DetectorInterface
{
    private const SUSPICIOUS_MULTIPLIER = 1;
    private const CRITICAL_MULTIPLIER = 20;

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
            'select', 'insert', 'update', 'drop', 'alter',
            'rename', 'replace', 'delete', 'desc', 'describe', 'shutdown', 'show', 'backup', 'restore',
            'union', 'create', 'all', 'distinct',
            'delayed', 'ignore', 'into', 'from', 'set', 'quick', 'temporary', 'concurrent', 'local',
            'replace', 'partition', 'table'
        ];
    }

    /**
     * @return array
     */
    private function getCriticalSearchPatterns(): array
    {
        return [
            'load data', 'distinctrow', 'low_priority', 'high_priority', 'straight_join',
            'sql_small_result', 'sql_big_result', 'sql_buffer_result', 'sql_cache', 'sql_no_cache',
            'sql_calc_found_rows', 'infile'
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
            'tags' => $finalScore > 0 ? [Tags::SQLI] : []
        ]);
    }
}
