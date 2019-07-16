<?php
declare(strict_types=1);

namespace Edoardo\Ids\Model\Detector;

use Edoardo\Ids\Model\DetectorInterface;
use Edoardo\Ids\Model\SecurityThreat;
use Edoardo\Ids\Model\SecurityThreatFactory;
use Edoardo\Ids\Model\Tags;
use Magento\Framework\App\RequestInterface;

class WPcsrf implements DetectorInterface
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

        // https://www.cvedetails.com/cve/CVE-2019-9787/
        // https://blog.ripstech.com/2019/wordpress-csrf-to-rce/
        // CVE-2019-9787
    

        if (strpos($this->request->getPathInfo(), '/wp-admin/includes/ajax-actions') !== false) {
            $score = 20;
        } else if (strpos($this->request->getPathInfo(), '/wp-includes/comment') !== false) {
            $score = 20;  // lo voglio solo loggare, non è una minaccia ma voglio capire cosa stanno facendo
        }

        return $this->securityThreatFactory->create([
            'impact' => $score,
            'tags' => $score > 0 ? [Tags::XSS, Tags::CSRF] : []
        ]);
    }
}


