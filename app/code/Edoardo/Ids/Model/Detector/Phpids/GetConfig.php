<?php
/** @noinspection PhpDocMissingThrowsInspection */
declare(strict_types=1);

namespace Edoardo\Ids\Model\Detector\Phpids;

use Magento\Framework\Filesystem\DirectoryList;

class GetConfig
{
    /**
     * @var DirectoryList
     */
    private $directoryList;

    /**
     * @param DirectoryList $directoryList
     */
    public function __construct(
        DirectoryList $directoryList
    ) {
        $this->directoryList = $directoryList;
    }

    /**
     * @return array
     */
    public function execute(): array
    {
        /** @noinspection PhpUnhandledExceptionInspection */
        $etcPath = $this->directoryList->getPath('etc');

        /** @noinspection PhpUnhandledExceptionInspection */
        $tmpPath = $this->directoryList->getPath('tmp');

        return [
            'General' => [
                'filter_type' => 'xml',
                'base_path' => $this->directoryList->getRoot(),
                'use_base_path' => false,
                'filter_path' => $etcPath . '/edoardo_ids.xml',
                'tmp_path' => $tmpPath,
                'scan_keys' => false,
                'HTML_Purifier_Cache' => 'vendors/htmlpurifier/HTMLPurifier/DefinitionCache/Serializer',
                'exceptions' => []
            ],
            'Caching' => [
                'caching' => 'none'
            ]
        ];
    }
}
