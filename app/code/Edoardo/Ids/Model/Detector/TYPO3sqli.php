<?php
declare(strict_types=1);

namespace Edoardo\Ids\Model\Detector;

use Edoardo\Ids\Model\DetectorInterface;
use Edoardo\Ids\Model\SecurityThreat;
use Edoardo\Ids\Model\SecurityThreatFactory;
use Edoardo\Ids\Model\Tags;
use Magento\Framework\App\RequestInterface;

class TYPO3sqli implements DetectorInterface
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

        // https://www.exploitalert.com/view-details.html?id=19876
        // https://www.cvedetails.com/cve/CVE-2008-4658/

        // Estensione di TYPO3, JobControl
        // CVE--2008-4658
    

         if (strpos($this->request->getPathInfo(), '/typo3/jobs') !== false) {                              // XSS parametro 'keyword' non sanitarizzato permette XSS reflected                
            $score = 20; // lo voglio solo loggare, non è una minaccia ma voglio capire cosa stanno facendo
        } else if (strpos($this->request->getPathInfo(), '/jobs') !== false)  {                                     // SQLi funzione job ricerca nel db ma dei campi non sanitarizzati
            $score = 20; 
        }


        return $this->securityThreatFactory->create([
            'impact' => $score,
            'tags' => $score > 0 ? [Tags::SQLI, Tags::XSS] : []
        ]);
    }
}

