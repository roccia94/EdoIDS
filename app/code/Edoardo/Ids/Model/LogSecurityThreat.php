<?php
declare(strict_types=1);

namespace Edoardo\Ids\Model;

use Magento\Framework\App\Filesystem\DirectoryList;
use Magento\Framework\App\RequestInterface;
use Magento\Framework\Exception\FileSystemException;
use Magento\Framework\HTTP\PhpEnvironment\RemoteAddress;
use Magento\Framework\Logger\Monolog;
use Magento\Framework\Logger\MonologFactory;
use Magento\Framework\Stdlib\DateTime\DateTime;
use Monolog\Handler\StreamHandler;


class LogSecurityThreat
{
    private const LOG_FILE = 'edoardo_ids.log';

    /**
     * @var Monolog
     */
    private $monolog;

    /**
     * @var RemoteAddress
     */
    private $remoteAddress;

    /**
     * @var DateTime
     */
    private $dateTime;

    /**
     * @var GetRequestPayload
     */
    private $getRequestPayload;

    /**
     * @var RequestInterface
     */
    private $request;

    /**
     * @var Config
     */
    private $config;

    /**
     * @param DateTime $dateTime
     * @param RequestInterface $request
     * @param GetRequestPayload $getRequestPayload
     * @param RemoteAddress $remoteAddress
     * @param MonologFactory $monologFactory
     * @param DirectoryList $directoryList
     * @param Config $config
     * @throws FileSystemException
     */
    public function __construct(
        DateTime $dateTime,
        RequestInterface $request,
        GetRequestPayload $getRequestPayload,
        RemoteAddress $remoteAddress,
        MonologFactory $monologFactory,
        DirectoryList $directoryList,
        Config $config
    ) {
        $this->config = $config;
        $this->dateTime = $dateTime;
        $this->remoteAddress = $remoteAddress;
        $this->getRequestPayload = $getRequestPayload;
        $this->request = $request;
        $this->monolog = $monologFactory->create();
        $this->monolog->setHandlers([]);
        $this->monolog->pushHandler(
            new StreamHandler(
                $directoryList->getPath(DirectoryList::VAR_DIR) . '/log/' . self::LOG_FILE
            )
        );
    }

    /**
     * @param SecurityThreat $report
     */
    public function execute(SecurityThreat $report): void
    {
        $context = [
            'url' => $this->request->getPathInfo(),
            'payload' => $this->getRequestPayload->execute()
        ];

        $message = sprintf(
            '%s [%s] [%s] Score: %d - Tags: %s',
            $this->dateTime->gmtDate(),
            $this->remoteAddress->getRemoteAddress(),
            implode(', ', $report->getModules()),
            $report->getImpact(),
            implode(', ', $report->getTags())
        );

        if ($report->getImpact() >= $this->config->getMinScoreToStop()) {
            $this->monolog->crit($message, $context);
        } else {
            $this->monolog->warn($message, $context);
        }
    }
}
