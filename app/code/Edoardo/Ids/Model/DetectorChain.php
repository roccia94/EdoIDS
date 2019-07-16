<?php
declare(strict_types=1);

namespace Edoardo\Ids\Model;

class DetectorChain implements DetectorInterface
{
    /**
     * @var array
     */
    private $detectors;

    /**
     * @var SecurityThreatFactory
     */
    private $securityThreatFactory;

    /**
     * @var FilterRequest
     */
    private $filterRequest;

    /**
     * @param array $detectors
     * @param FilterRequest $filterRequest
     * @param SecurityThreatFactory $securityThreatFactory
     */
    public function __construct(
        array $detectors,
        FilterRequest $filterRequest,
        SecurityThreatFactory $securityThreatFactory
    ) {
        $this->detectors = $detectors;
        $this->securityThreatFactory = $securityThreatFactory;
        $this->filterRequest = $filterRequest;
    }

    /**
     * @inheritDoc
     */
    public function execute(array $requestPayload): SecurityThreat
    {
        $tags = [];
        $modules = [];
        $impact = 0;

        $requestPayload = $this->filterRequest->execute($requestPayload);

        foreach ($this->detectors as $detectorCode => $detector) {
            /** @var DetectorInterface $detector */
            $threat = $detector->execute($requestPayload);

            if ($threat->getImpact() > 0) {
                $impact += $threat->getImpact();
                $tags = array_merge($tags, $threat->getTags());
                $modules[] = $detectorCode;
            }
        }

        return $this->securityThreatFactory->create([
            'impact' => $impact,
            'tags' => array_unique($tags),
            'modules' => $modules
        ]);
    }
}