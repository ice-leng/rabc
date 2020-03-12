<?php

declare(strict_types=1);

namespace Lengbin\YiiDb\Rbac;

class Role extends Item
{
    public function getType(): string
    {
        return self::TYPE_ROLE;
    }
}
