<?php
declare(strict_types=1);

namespace Edoardo\Ids\Model\Detector;

use Edoardo\Ids\Model\DetectorInterface;
use Edoardo\Ids\Model\GetMatchesCount;
use Edoardo\Ids\Model\SecurityThreat;
use Edoardo\Ids\Model\SecurityThreatFactory;
use Edoardo\Ids\Model\Tags;

class HtmlAttributes implements DetectorInterface
{
    private const MULTIPLIER = 10;

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
    private function getSearchPatterns(): array
    {
        $genericAttributesRegex = '/\\b'
            .'('
                .'src(alt|doc|lang|set)?|'
                .'style|'
                .'class|'
                .'code(base)?|'
                .'href|'
                .'name|'
                .'action|'
                .'target|'
                .'formaction|'
                .'crossorigin|'
                .'download|'
                .'http\\-equiv|'
                .'placeholder|'
                .'rel|'
                .'poster|'
                .'alt|'
                .'title|'
                .'data(\\-(\\w+))*'
            .')\s*=/';

        $onEventsHandler = '/(\\b|\\W)on\\w+\s*=/';  // onclick= , onload= , ecc...

        return [
            $genericAttributesRegex,
            $onEventsHandler
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
                $score += $this->getMatchesCount->execute($value, $this->getSearchPatterns());
            }
        }

        return $this->securityThreatFactory->create([
            'impact' => $score * self::MULTIPLIER,
            'tags' => $score > 0 ? [Tags::RCE, Tags::XSS] : []
        ]);
    }
}
