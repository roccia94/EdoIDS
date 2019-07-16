<?php
declare(strict_types=1);

namespace Edoardo\Ids\Model;

class FilterRequest
{
    /**
     * @param string $value
     * @return bool
     */
    private function isBase64(string $value): bool
    {
        return (bool) preg_match('/^(?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=)?$/', $value);
    }

    /**
     * @param array $request
     * @return array
     */
    public function execute(array $request): array
    {
        foreach ($request as $k => $v) {
            if (is_array($v)) {
                $request[$k] = $this->execute($v);
                continue;
            }

            if ($this->isBase64($request[$k])) {
                $request[$k] = base64_decode($request[$k], true) . ' ' . $request[$k];
            }

            $htmlEntity = html_entity_decode($request[$k], ENT_QUOTES | ENT_HTML5, 'UTF-8');

            if ($request[$k] !== $htmlEntity) {
                $request[$k] = $htmlEntity;
            }

            $urlDecode = urldecode($request[$k]);
            if ($request[$k] !== $urlDecode) {
                $request[$k] = $urlDecode;
            }

            $request[$k] = preg_replace("/[\r\n\s]+/", ' ', trim($request[$k]));
        }

        return $request;
    }
}
