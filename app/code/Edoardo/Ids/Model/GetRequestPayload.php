<?php
declare(strict_types=1);

namespace Edoardo\Ids\Model;

class GetRequestPayload
{
    /**
     * @return array
     */
    public function execute(): array
    {
        return [
            'GET' => $_GET,
            'POST' => $_POST,
        ];
    }
}
