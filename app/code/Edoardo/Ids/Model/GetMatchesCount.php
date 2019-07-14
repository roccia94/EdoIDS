<?php
declare(strict_types=1);

namespace Edoardo\Ids\Model;

class GetMatchesCount
{
    /**
     * @param string $value
     * @param array $searches
     * @return int
     */
    public function execute(string $value, array $searches): int
    {
        $value = mb_strtolower($value);

        $count = 0;

        foreach ($searches as $search) {
            $isRegex = strpos($search, '/') !== false;
            if ($isRegex) {
                if (preg_match_all($search, $value, $matches)) {
                    $count += count($matches);
                }
            } else {
                $count += substr_count($value, $search);
            }
        }

        return $count;
    }
}
