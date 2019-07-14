<?php
declare(strict_types=1);

namespace Edoardo\Ids\Model\Detector;

use Edoardo\Ids\Model\DetectorInterface;
use Edoardo\Ids\Model\SecurityThreat;
use Edoardo\Ids\Model\SecurityThreatFactory;
use Edoardo\Ids\Model\Tags;
use Magento\Framework\App\RequestInterface;

class Prodsecbug2198 implements DetectorInterface
{
    private const MULTIPLIER = 50;

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
        // https://www.ambionics.io/blog/magento-sqli
        // https://magento.com/security/patches/magento-2.3.1-2.2.8-and-2.1.17-security-update
        // PRODSECBUG-2198: SQL Injection vulnerability through an unauthenticated user

        $score = 0;
        if (strpos($this->request->getPathInfo(), '/catalog/product_frontend_action/synchronize') !== false) {
            $score = 1;
        }

        return $this->securityThreatFactory->create([
            'impact' => $score * self::MULTIPLIER,
            'tags' => $score > 0 ? [Tags::SQLI] : []
        ]);
    }
}
