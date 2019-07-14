<?php
declare(strict_types=1);

namespace Edoardo\Ids\Model;

class SecurityThreat
{
    /**
     * @var int
     */
    private $impact;

    /**
     * @var array
     */
    private $tags;

    /**
     * @var array
     */
    private $modules;

    /**
     * @param int $impact
     * @param array $tags
     * @param array $modules
     */
    public function __construct(
        int $impact,
        array $tags,
        array $modules = []
    ) {
        $this->impact = $impact;
        $this->tags = $tags;
        $this->modules = $modules;
    }

    /**
     * @return array
     */
    public function getModules(): array
    {
        return $this->modules;
    }

    /**
     * @return int
     */
    public function getImpact(): int
    {
        return $this->impact;
    }

    /**
     * @return array
     */
    public function getTags(): array
    {
        return $this->tags;
    }
}
