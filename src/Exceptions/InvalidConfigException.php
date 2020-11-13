<?php

declare(strict_types=1);

namespace Lengbin\YiiSoft\Rbac\Exceptions;

/**
 * InvalidConfigException represents an exception caused by incorrect object configuration.
 */
class InvalidConfigException extends \Exception implements RbacExceptionInterface
{
    /**
     * @return string the user-friendly name of this exception
     */
    public function getName()
    {
        return 'Invalid Configuration';
    }
}
