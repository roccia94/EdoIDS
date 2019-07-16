<?php
declare(strict_types=1);

namespace Edoardo\Ids\Model\Detector;

use Edoardo\Ids\Model\DetectorInterface;
use Edoardo\Ids\Model\SecurityThreat;
use Edoardo\Ids\Model\SecurityThreatFactory;
use Edoardo\Ids\Model\Tags;
use Magento\Framework\App\RequestInterface;

class DRUPopred implements DetectorInterface
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

        // https://www.exploitalert.com/view-details.html?id=32364
        // https://www.drupal.org/sa-contrib-2019-012

        //Open redirect attraverso pub content download di drupal
    

        if (strpos($this->request->getPathInfo(), '/web/modules/pubdlcnt/pubdlcnt.php') !== false) {
            $score = 20;   // lo voglio solo loggare, non è una minaccia ma voglio capire cosa stanno facendo
        } else if (strpos($this->request->getPathInfo(), '/sites/all/modules/pubdlcnt/pubdlcnt.php') !== false) {                                        
            $score = 20; 
        } else if (strpos($this->request->getPathInfo(), '/sites/all/modules/patched/pubdlcnt/pubdlcnt.php') !== false) {
            $score = 20; 
        } else if (strpos($this->request->getPathInfo(), '/sites/all/modules/contributed/other/pubdlcnt/pubdlcnt.php') !== false) {
            $score = 20; 
        }

        return $this->securityThreatFactory->create([
            'impact' => $score,
            'tags' => $score > 0 ? [Tags::XSS, Tags::RCE] : []
        ]);
    }
}

