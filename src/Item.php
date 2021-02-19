<?php

declare(strict_types=1);

namespace Lengbin\YiiSoft\Rbac;

/**
 * For more details and usage information on Item, see the [guide article on security authorization](guide:security-authorization).
 */
abstract class Item implements ItemInterface
{
    public const TYPE_ROLE = 'role';
    public const TYPE_PERMISSION = 'permission';

    /**
     * @var string the name of the item. This must be globally unique.
     */
    private $name;

    /**
     * @var string the item description
     */
    private $description = '';

    /**
     * @var string name of the rule associated with this item
     */
    private $ruleName = null;

    /**
     * @var int UNIX timestamp representing the item creation time
     */
    private $createdAt = null;

    /**
     * @var int UNIX timestamp representing the item updating time
     */
    private $updatedAt = null;

    /**
     * @var int enable
     */
    private $enable = 1;

    public function __construct(string $name)
    {
        $this->name = $name;
    }

    abstract public function getType(): string;

    public function getName(): string
    {
        return $this->name;
    }

    public function withName(string $name): self
    {
        $new = clone $this;
        $new->name = $name;
        return $new;
    }

    public function withDescription(string $description): self
    {
        $new = clone $this;
        $new->description = $description;
        return $new;
    }

    public function getDescription(): string
    {
        return $this->description;
    }

    public function withRuleName(?string $ruleName): self
    {
        $new = clone $this;
        $new->ruleName = $ruleName;
        return $new;
    }

    public function getRuleName(): ?string
    {
        return $this->ruleName;
    }

    public function withCreatedAt(int $createdAt): self
    {
        $new = clone $this;
        $new->createdAt = $createdAt;
        return $new;
    }

    public function getCreatedAt(): ?int
    {
        return $this->createdAt;
    }

    public function withUpdatedAt(int $updatedAt): self
    {
        $new = clone $this;
        $new->updatedAt = $updatedAt;
        return $new;
    }

    public function getUpdatedAt(): ?int
    {
        return $this->updatedAt;
    }

    public function hasCreatedAt(): bool
    {
        return $this->createdAt !== null;
    }

    public function hasUpdatedAt(): bool
    {
        return $this->updatedAt !== null;
    }

    /**
     * @return int
     */
    public function getEnable(): int
    {
        return $this->enable;
    }

    /**
     * @param int $enable
     *
     * @return Item
     */
    public function withEnable(int $enable): Item
    {
        $new = clone $this;
        $new->enable = $enable;
        return $new;
    }

    public function getAttributes(): array
    {
        return [
            'name'        => $this->getName(),
            'description' => $this->getDescription(),
            'rule_name'   => $this->getRuleName(),
            'type'        => $this->getType(),
            'updated_at'  => $this->getUpdatedAt(),
            'created_at'  => $this->getCreatedAt(),
            'enable'      => $this->getEnable()
        ];
    }
}
