<?php

namespace Lengbin\YiiSoft\Rbac;

class Menu implements ItemInterface
{
    private $name;
    private $createdAt;
    private $updatedAt;
    /**
     * @var string
     */
    private $pid;

    /**
     * @var string
     */
    private $icon;

    /**
     * @var string
     */
    private $path;

    /**
     * @var int
     */
    private $sort;

    /**
     * @var string
     */
    private $template;

    /**
     * @var string
     */
    private $role;

    /**
     * @var int enable
     */
    private $enable = 1;

    public function __construct(string $name)
    {
        $this->name = $name;
    }

    public function getName(): string
    {
        return $this->name;
    }

    public function withName(string $name): Menu
    {
        $new = clone $this;
        $new->name = $name;
        return $new;
    }

    public function withCreatedAt(int $createdAt): Menu
    {
        $new = clone $this;
        $new->createdAt = $createdAt;
        return $new;
    }

    public function getCreatedAt(): ?int
    {
        return $this->createdAt;
    }

    public function withUpdatedAt(int $updatedAt): Menu
    {
        $new = clone $this;
        $new->updatedAt = $updatedAt;
        return $new;
    }

    public function getUpdatedAt(): ?int
    {
        return $this->updatedAt;
    }

    /**
     * @return string
     */
    public function getPid(): string
    {
        return $this->pid;
    }

    /**
     * @param string $pid
     *
     * @return Menu
     */
    public function withPid(string $pid): Menu
    {
        $new = clone $this;
        $new->pid = $pid;
        return $new;
    }

    /**
     * @return string|null
     */
    public function getIcon(): ?string
    {
        return $this->icon;
    }

    /**
     * @param string $icon
     *
     * @return Menu
     */
    public function withIcon(string $icon): Menu
    {
        $new = clone $this;
        $new->icon = $icon;
        return $new;
    }

    /**
     * @return string
     */
    public function getPath(): string
    {
        return $this->path;
    }

    /**
     * @param string $path
     *
     * @return Menu
     */
    public function withPath(string $path): Menu
    {
        $new = clone $this;
        $new->path = $path;
        return $new;
    }

    /**
     * @return int
     */
    public function getSort(): int
    {
        return $this->sort;
    }

    /**
     * @param int $sort
     *
     * @return Menu
     */
    public function withSort(int $sort): Menu
    {
        $new = clone $this;
        $new->sort = $sort;
        return $new;
    }

    /**
     * @return string|null
     */
    public function getTemplate(): ?string
    {
        return $this->template;
    }

    /**
     * @param string $template
     *
     * @return Menu
     */
    public function withTemplate(string $template): Menu
    {
        $new = clone $this;
        $new->template = $template;
        return $new;
    }

    /**
     * @return string|null
     */
    public function getRole(): ?string
    {
        return $this->role;
    }

    /**
     * @param string $role
     *
     * @return Menu
     */
    public function withRole(string $role): Menu
    {
        $new = clone $this;
        $new->role = $role;
        return $new;
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
     * @return Menu
     */
    public function withEnable(int $enable): Menu
    {
        $new = clone $this;
        $new->enable = $enable;
        return $new;
    }

    public function getAttributes(): array
    {
        return [
            'name'       => $this->getName(),
            'pid'        => $this->getPid(),
            'icon'       => $this->getIcon(),
            'path'       => $this->getPath(),
            'template'   => $this->getTemplate(),
            'role'       => $this->getRole(),
            'sort'       => $this->getSort(),
            'enable'     => $this->getEnable(),
            'updated_at' => $this->getUpdatedAt(),
            'created_at' => $this->getCreatedAt(),
        ];
    }
}
