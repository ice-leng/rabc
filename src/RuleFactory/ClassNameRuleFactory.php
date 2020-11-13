<?php

declare(strict_types=1);

namespace Lengbin\YiiSoft\Rbac\RuleFactory;

use Lengbin\YiiSoft\Rbac\Rule;
use Lengbin\YiiSoft\Rbac\RuleFactoryInterface;

class ClassNameRuleFactory implements RuleFactoryInterface
{
    public function create(string $name): Rule
    {
        return new $name();
    }
}
