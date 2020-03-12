<?php

declare(strict_types=1);

namespace Common\Rbac\RuleFactory;

use Common\Rbac\Rule;
use Common\Rbac\RuleFactoryInterface;

class ClassNameRuleFactory implements RuleFactoryInterface
{
    public function create(string $name): Rule
    {
        return new $name();
    }
}
