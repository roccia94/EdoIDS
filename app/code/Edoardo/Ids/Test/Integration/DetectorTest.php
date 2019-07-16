<?php
declare(strict_types=1);

namespace Edoardo\Ids\Test\Integration;

use Edoardo\Ids\Model\DetectorInterface;
use PHPUnit\Framework\TestCase;
use Magento\TestFramework\Helper\Bootstrap;

class DetectorTest extends TestCase
{
    private const TRIGGERING_VALUE = 15;

    /**
     * @var DetectorInterface
     */
    private $detector;

    /**
     * @inheritdoc
     */
    protected function setUp()
    {
        $this->detector = Bootstrap::getObjectManager()->get(DetectorInterface::class);
    }

    /**
     * @param string $file
     * @return array
     */
    private function getAttackPatterns(string $file): array
    {
        $res = [];
        $attacks = file(__DIR__ . '/_files/' . $file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        foreach ($attacks as $attack) {
            $res[$attack] = ['attack' => $attack];
        }

        return $res;
    }

    /**
     * @return array
     */
    public function sqliDataProvider(): array
    {
        return $this->getAttackPatterns('sqli.txt');
    }

    /**
     * @return array
     */
    public function xssDataProvider(): array
    {
        return $this->getAttackPatterns('xss.txt');
    }

    /**
     * @return array
     */
    public function rceDataProvider(): array
    {
        return $this->getAttackPatterns('rce.txt');
    }

    /**
     * @return array
     */
    public function traversalDataProvider(): array
    {
        return $this->getAttackPatterns('traversal.txt');
    }

    /**
     * @return array
     */
    public function phpCommandDataProvider(): array
    {
        return $this->getAttackPatterns('phpcommand.txt');
    }

    /**
     * @return array
     */
    public function negativesDataProvider(): array
    {
        return $this->getAttackPatterns('negatives.txt');
    }

    /**
     * @param string $attack
     * @dataProvider sqliDataProvider
     */
    public function testSQLi(string $attack): void
    {
        $res = $this->detector->execute(['POST' => ['someParam' => $attack]]);
        $this->assertGreaterThanOrEqual(self::TRIGGERING_VALUE, $res->getImpact());
    }

    /**
     * @param string $attack
     * @dataProvider xssDataProvider
     */
    public function testXSS(string $attack): void
    {
        $res = $this->detector->execute(['POST' => ['someParam' => $attack]]);
        $this->assertGreaterThanOrEqual(self::TRIGGERING_VALUE, $res->getImpact());
    }

    /**
     * @param string $attack
     * @dataProvider rceDataProvider
     */
    public function testRCE(string $attack): void
    {
        $res = $this->detector->execute(['POST' => ['someParam' => $attack]]);
        $this->assertGreaterThanOrEqual(self::TRIGGERING_VALUE, $res->getImpact());
    }

    /**
     * @param string $attack
     * @dataProvider traversalDataProvider
     */
    public function testTraversal(string $attack): void
    {
        $res = $this->detector->execute(['POST' => ['someParam' => $attack]]);
        $this->assertGreaterThanOrEqual(self::TRIGGERING_VALUE, $res->getImpact());
    }

    /**
     * @param string $attack
     * @dataProvider phpCommandDataProvider
     */
    public function testPhpCommand(string $attack): void
    {
        $res = $this->detector->execute(['POST' => ['someParam' => $attack]]);
        $this->assertGreaterThanOrEqual(self::TRIGGERING_VALUE, $res->getImpact());
    }

    /**
     * @param string $attack
     * @dataProvider negativesDataProvider
     */
    public function testNegatives(string $attack): void
    {
        $res = $this->detector->execute(['POST' => ['someParam' => $attack]]);
        $this->assertLessThanOrEqual(self::TRIGGERING_VALUE, $res->getImpact());
    }
}
