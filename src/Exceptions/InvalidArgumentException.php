<?php

declare(strict_types=1);

namespace Lengbin\YiiSoft\Rbac\Exceptions;

/**
 * InvalidArgumentException represents an exception caused by invalid arguments passed to a method.
 */
class InvalidArgumentException extends \BadMethodCallException implements RbacExceptionInterface
{
    /**
     * @return string the user-friendly name of this exception
     */
    public function getName(): string
    {
        return 'Invalid Argument';
    }

    public function getSolution(): ?string
    {
        return null;
    }
}
