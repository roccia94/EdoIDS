<?php
declare(strict_types=1);

namespace Edoardo\Ids\Model\Detector;

use Edoardo\Ids\Model\DetectorInterface;
use Edoardo\Ids\Model\GetMatchesCount;
use Edoardo\Ids\Model\SecurityThreat;
use Edoardo\Ids\Model\SecurityThreatFactory;
use Edoardo\Ids\Model\Tags;

class RFIredirect implements DetectorInterface
{
    private const MULTIPLIER = 40;

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
     * @inheritDoc
     */
    public function execute(array $requestPayload): SecurityThreat
    {
        $score = 0;

        foreach ($requestPayload as $type => $data) {
            foreach ($data as $field => $value) {
                $score += $this->getMatchesCount->execute($value, ['/\\w+:\/\//']);
            }
        }

        return $this->securityThreatFactory->create([
            'impact' => $score * self::MULTIPLIER,
            'tags' => $score > 0 ? [Tags::XSS, Tags::RCE] : []
        ]);
    }
}
