<?php

declare(strict_types=1);

namespace Lengbin\YiiSoft\Rbac\Exceptions;


/**
 * InvalidCallException represents an exception caused by calling a method in a wrong way.
 */
class InvalidCallException extends \BadMethodCallException implements RbacExceptionInterface
{
    public function getName(): string
    {
        return 'Invalid Call';
    }

    public function getSolution(): ?string
    {
        return null;
    }
}
