<?php
declare(strict_types=1);

namespace Edoardo\Ids\Model;

class Tags
{
    public const XSS = 'xss'; // XSS
    public const RCE = 'rce'; // Remote code execution
    public const SQLI = 'sqli'; // SQL injection
    public const LFE = 'lfe'; // Local file exploit
}
