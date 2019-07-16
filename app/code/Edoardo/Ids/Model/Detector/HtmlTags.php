<?php
declare(strict_types=1);

namespace Edoardo\Ids\Model\Detector;

use Edoardo\Ids\Model\DetectorInterface;
use Edoardo\Ids\Model\SecurityThreat;
use Edoardo\Ids\Model\SecurityThreatFactory;
use Edoardo\Ids\Model\Tags;

class HtmlTags implements DetectorInterface
{
    private const MULTIPLIER = 10;

    /**
     * @var SecurityThreatFactory
     */
    private $securityThreatFactory;

    /**
     * @param SecurityThreatFactory $securityThreatFactory
     */
    public function __construct(
        SecurityThreatFactory $securityThreatFactory
    ) {
        $this->securityThreatFactory = $securityThreatFactory;
    }

    /**
     * @return array
     * @SuppressWarnings(PHPMD.ExcessiveMethodLength)
     */
    private function getHtmlTags(): array
    {
        // https://www.w3schools.com/tags/
        return [
            '!DOCTYPE',
            'a',
            'abbr',
            'address',
            'area',
            'article',
            'aside',
            'audio',
            'b',
            'base',
            'bdi',
            'bdo',
            'blockquote',
            'body',
            'br',
            'button',
            'canvas',
            'caption',
            'cite',
            'code',
            'col',
            'colgroup',
            'data',
            'datalist',
            'dd',
            'del',
            'details',
            'dfn',
            'dialog',
            'div',
            'dl',
            'dt',
            'em',
            'embed',
            'fieldset',
            'figcaption',
            'figure',
            'footer',
            'form',
            'h1',
            'h2',
            'h3',
            'h4',
            'h5',
            'h6',
            'head',
            'header',
            'hgroup',
            'hr',
            'html',
            'i',
            'iframe',
            'img',
            'input',
            'ins',
            'kbd',
            'keygen',
            'label',
            'legend',
            'li',
            'link',
            'main',
            'map',
            'mark',
            'menu',
            'menuitem',
            'meta',
            'meter',
            'nav',
            'noscript',
            'object',
            'ol',
            'optgroup',
            'option',
            'output',
            'p',
            'param',
            'pre',
            'progress',
            'q',
            'rb',
            'rp',
            'rt',
            'rtc',
            'ruby',
            's',
            'samp',
            'script',
            'section',
            'select',
            'small',
            'source',
            'span',
            'strong',
            'style',
            'sub',
            'summary',
            'sup',
            'table',
            'tbody',
            'td',
            'template',
            'textarea',
            'tfoot',
            'th',
            'thead',
            'time',
            'title',
            'tr',
            'track',
            'u',
            'ul',
            'var',
            'video',
            'wbr',
        ];
    }
    
    /**
     * @inheritDoc
     */
    public function execute(array $requestPayload): SecurityThreat
    {
        $htmlTags = $this->getHtmlTags();

        $score = 0;

        foreach ($requestPayload as $type => $data) {
            foreach ($data as $field => $value) {
                if (preg_match_all('/<(\w+)/', $value, $matches)) {
                    foreach ($matches[1] as $match) {
                        if (in_array(mb_strtolower($match), $htmlTags, true)) {
                            $score += self::MULTIPLIER;
                        }
                    }
                }
            }
        }

        return $this->securityThreatFactory->create([
            'impact' => $score,
            'tags' => $score > 0 ? [Tags::XSS] : []
        ]);
    }
}
