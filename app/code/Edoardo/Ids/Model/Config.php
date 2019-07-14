<?php
declare(strict_types=1);

namespace Edoardo\Ids\Model;

use Magento\Framework\App\Config\ScopeConfigInterface;

class Config
{
    private const XML_PATH_ENABLED = 'edoardo_ids/general/enabled';
    private const XML_PATH_MIN_SCORE_LOG = 'edoardo_ids/general/min_score_log';
    private const XML_PATH_MIN_SCORE_STOP = 'edoardo_ids/general/min_score_stop';
    private const XML_PATH_WHITELIST = 'edoardo_ids/general/uri_whitelist';

    /**
     * @var ScopeConfigInterface
     */
    private $scopeConfig;

    /**
     * @param ScopeConfigInterface $scopeConfig
     */
    public function __construct(
        ScopeConfigInterface $scopeConfig
    ) {
        $this->scopeConfig = $scopeConfig;
    }

    /**
     * @return bool
     */
    public function isEnabled(): bool
    {
        return (bool) $this->scopeConfig->getValue(self::XML_PATH_ENABLED);
    }

    /**
     * @return int
     */
    public function getMinScoreToLog(): int
    {
        return (int) max(1, $this->scopeConfig->getValue(self::XML_PATH_MIN_SCORE_LOG));
    }

    /**
     * @return int
     */
    public function getMinScoreToStop(): int
    {
        return (int) max(
            $this->getMinScoreToLog(),
            $this->scopeConfig->getValue(self::XML_PATH_MIN_SCORE_STOP)
        );
    }

    /**
     * @return array
     */
    public function getUriWhitelist(): array
    {
        return preg_split('/[\s\n]+/', $this->scopeConfig->getValue(self::XML_PATH_WHITELIST));
    }
}
