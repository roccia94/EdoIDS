<?php
declare(strict_types=1);

namespace Edoardo\Ids\Model\Detector;

use Edoardo\Ids\Model\DetectorInterface;
use Edoardo\Ids\Model\GetMatchesCount;
use Edoardo\Ids\Model\SecurityThreat;
use Edoardo\Ids\Model\SecurityThreatFactory;
use Edoardo\Ids\Model\Tags;
use Magento\Framework\App\RequestInterface;

class TYPO3phpcode implements DetectorInterface
{
   
/**
     * @var SecurityThreatFactory
     */
    private $securityThreatFactory;

    /**
     * @var RequestInterface
     */
    private $request;

    /**
     * @param RequestInterface $request
     * @param SecurityThreatFactory $securityThreatFactory
     */
    public function __construct(
        RequestInterface $request,
        SecurityThreatFactory $securityThreatFactory
    ) {
        $this->securityThreatFactory = $securityThreatFactory;
        $this->request = $request;
    }

    /**
     * @inheritDoc
     */
    public function execute(array $requestPayload): SecurityThreat
    {
        $score = 0;

        // https://www.cvedetails.com/cve/CVE-2017-14251/
        // 
        // CVE-2017-14251
    

         if (strpos($this->request->getPathInfo(), '/sysext/core/Classes/Core/SystemEnvironmentBuilder') !== false) {
            $score = 20; // lo voglio solo loggare, non è una minaccia ma voglio capire cosa stanno facendo
        } 
        return $this->securityThreatFactory->create([
            'impact' => $score,
            'tags' => $score > 0 ? [Tags::RCE] : []
        ]);
    }
}


