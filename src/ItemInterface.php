<?php

declare(strict_types=1);

namespace Lengbin\YiiDb\Rbac;

/**
 * Common interface for authorization items:
 *
 * - Role
 * - Permission
 * - Rule
 */
interface ItemInterface
{
    public function getName(): string;

    public function getAttributes(): array;
}
