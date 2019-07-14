<?php
declare(strict_types=1);

namespace Edoardo\Ids\Model;

use Magento\Framework\App\DeploymentConfig;
use Magento\Framework\App\RequestInterface;

class IsAdminPath
{
    /**
     * @var DeploymentConfig
     */
    private $deploymentConfig;

    /**
     * @var RequestInterface
     */
    private $request;

    /**
     * @param DeploymentConfig $deploymentConfig
     * @param RequestInterface $request
     */
    public function __construct(
        DeploymentConfig $deploymentConfig,
        RequestInterface $request
    ) {
        $this->deploymentConfig = $deploymentConfig;
        $this->request = $request;
    }

    /**
     * @return bool
     */
    public function execute(): bool
    {
        $uri = $this->request->getRequestUri();
        $uri = filter_var($uri, FILTER_SANITIZE_URL);
        $uri = preg_replace('|/+|', '/', $uri);
        $uri = preg_replace('|^/.+?\.php|', '', $uri);

        $uri = parse_url($uri, PHP_URL_PATH);

        $backendConfigData = $this->deploymentConfig->getConfigData('backend');
        $backendPath = $backendConfigData['frontName'];

        return (strpos($uri, "/$backendPath/") === 0) || preg_match("|/$backendPath$|", $uri);
    }
}
