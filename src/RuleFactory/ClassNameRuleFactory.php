<?php

declare(strict_types=1);

namespace Lengbin\YiiDb\Rbac\RuleFactory;

use Lengbin\YiiDb\Rbac\Rule;
use Lengbin\YiiDb\Rbac\RuleFactoryInterface;

class ClassNameRuleFactory implements RuleFactoryInterface
{
    public function create(string $name): Rule
    {
        return new $name();
    }
}
