<?php
declare(strict_types=1);

namespace Edoardo\Ids\Model;

interface DetectorInterface
{
    /**
     * Detect threat
     *
     * @param array $requestPayload
     * @return SecurityThreat
     */
    public function execute(array $requestPayload): SecurityThreat;
}