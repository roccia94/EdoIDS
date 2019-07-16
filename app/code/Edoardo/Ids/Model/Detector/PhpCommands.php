<?php
declare(strict_types=1);

namespace Edoardo\Ids\Model\Detector;

use Edoardo\Ids\Model\DetectorInterface;
use Edoardo\Ids\Model\GetMatchesCount;
use Edoardo\Ids\Model\SecurityThreat;
use Edoardo\Ids\Model\SecurityThreatFactory;
use Edoardo\Ids\Model\Tags;

class PhpCommands implements DetectorInterface
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
        return [
            '/_encode\\s*\\(/',
            '/_decode\\s*\\(/',
            '/gzinflate\\s*\\(/',
            '/gzdeflate\\s*\\(/',
            '/str_rot13\\s*\\(/',
            '/crypt\\s*\\(/',
            '/crc32\\s*\\(/',
            '/(raw)?url(encode|decode)\\s*\\(/',
            '/(chr|ord)\\s*\\(/',
            '/atob\\s*\\(/',
            '/\\`.+?\\`/',
            '/exec\\s*\\(/',
            '/system\\s*\\(/',
            '/passthru\\s*\\(/',
            '/popen\\s*\\(/',
            '/eval\\s*\\(/',
            '/phpinfo\\s*\\(/',
            '/(preg|ereg|eregi)_(replace|match|split|filter)([\\w\\_]+)*\\s*\\(/',
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
            'tags' => $score > 0 ? [Tags::RCE] : []
        ]);
    }
}
