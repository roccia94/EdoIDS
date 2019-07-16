<?php
declare(strict_types=1);

namespace Edoardo\Ids\Model\Detector;

use Edoardo\Ids\Model\DetectorInterface;
use Edoardo\Ids\Model\GetMatchesCount;
use Edoardo\Ids\Model\SecurityThreat;
use Edoardo\Ids\Model\SecurityThreatFactory;
use Edoardo\Ids\Model\Tags;

class JsF implements DetectorInterface
{
    private const MULTIPLIER = 20;

    /**
     * @var SecurityThreatFactory
     */
    private $securityThreatFactory;

    /**
     * @var GetMatchesCount
     */
    private $getMatchesCount;

    /**
     * @param SecurityThreatFactory $securityThreatFactory
     * @param GetMatchesCount $getMatchesCount
     */
    public function __construct(
        SecurityThreatFactory $securityThreatFactory,
        GetMatchesCount $getMatchesCount
    ) {
        $this->securityThreatFactory = $securityThreatFactory;
        $this->getMatchesCount = $getMatchesCount;
    }

    /**
     * @return array
     */
    private function getSearchPatterns(): array
    {
        // http://www.jsfuck.com/
        // https://github.com/aemkei/jsfuck/blob/master/jsfuck.js
        return [
            '![]',
            '[][[]]',
            '+[![]]',
            '+[]',
            '+!+[]',
            '!+[]',
        ];
    }

    /**
     * @inheritDoc
     */
    public function execute(array $requestPayload): SecurityThreat
    {
        $score = 0;

        foreach ($requestPayload as $type => $data) {
            foreach ($data as $field => $value) {
                $value = preg_replace('/\s+/', '', $value);

                $score += $this->getMatchesCount->execute($value, $this->getSearchPatterns());
            }
        }

        return $this->securityThreatFactory->create([
            'impact' => $score * self::MULTIPLIER,
            'tags' => $score > 0 ? [Tags::RCE] : []
        ]);
    }
}
