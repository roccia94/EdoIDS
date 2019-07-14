<?php
declare(strict_types=1);

namespace Edoardo\Ids\Plugin;

use Closure;
use Edoardo\Ids\Exception\IdsException;
use Edoardo\Ids\Model\CheckRequest;
use Edoardo\Ids\Model\Config;
use Magento\Framework\App\Response\Http;
use Magento\Framework\AppInterface;
use Magento\Framework\Exception\LocalizedException;

class ApplyFilter
{
    /**
     * @var Config
     */
    private $config;

    /**
     * @var CheckRequest
     */
    private $checkRequest;

    /**
     * @var Http
     */
    private $http;

    /**
     * @param Config $config
     * @param CheckRequest $checkRequest
     * @param Http $http
     */
    public function __construct(
        Config $config,
        CheckRequest $checkRequest,
        Http $http
    ) {
        $this->config = $config;
        $this->checkRequest = $checkRequest;
        $this->http = $http;
    }

    /**
     * @param AppInterface $subject
     * @param Closure $proceed
     * @return Http|mixed
     * @SuppressWarnings("PHPMD.UnusedFormalParameter")
     * @throws LocalizedException
     */
    public function aroundLaunch(AppInterface $subject, Closure $proceed)
    {
        if ($this->config->isEnabled()) {
            try {
                $this->checkRequest->execute();
            } catch (IdsException $e) {
                $this->http->setStatusCode(500);
                $this->http->setBody('<h1>500 - Security Exception</h1>');
                return $this->http;
            }
        }

        return $proceed($subject);
    }
}
