<?php

declare(strict_types=1);

namespace Lengbin\YiiSoft\Rbac\Manager;

use Lengbin\YiiSoft\Rbac\Assignment;
use Lengbin\YiiSoft\Rbac\Exceptions\InvalidArgumentException;
use Lengbin\YiiSoft\Rbac\Exceptions\InvalidCallException;
use Lengbin\YiiSoft\Rbac\Exceptions\InvalidConfigException;
use Lengbin\YiiSoft\Rbac\Item;
use Lengbin\YiiSoft\Rbac\Menu;
use Lengbin\YiiSoft\Rbac\Permission;
use Lengbin\YiiSoft\Rbac\Role;
use Lengbin\YiiSoft\Rbac\Rule;
use Lengbin\YiiSoft\Rbac\RuleFactoryInterface;
use Psr\Log\LoggerInterface;
use Psr\SimpleCache\CacheInterface;

/**
 * PhpManager represents an authorization manager that stores authorization
 * information in terms of a PHP script file.
 *
 * The authorization data will be saved to and loaded from three files
 * specified by [[itemFile]], [[assignmentFile]] and [[ruleFile]].
 *
 * PhpManager is mainly suitable for authorization data that is not too big
 * (for example, the authorization data for a personal blog system).
 * Use [[DbManager]] for more complex authorization data.
 *
 * For more details and usage information on PhpManager, see the [guide article on security authorization](guide:security-authorization).
 */
class PhpManager extends BaseManager
{
    /**
     * cache
     * @var CacheInterface $cache
     */
    protected $cache;

    /**
     * logger
     * @var LoggerInterface $logger
     */
    protected $logger;

    /**
     * name
     * @var string
     */
    protected $itemCacheName;

    /**
     * name
     * @var string
     */
    protected $assignmentCacheName;

    /**
     * @var string
     */
    protected $menuCacheName;

    /**
     * name
     * @var string
     */
    protected $ruleCacheName;

    /**
     * @var Item[]
     * format [itemName => item]
     */
    protected $items = [];

    /**
     * @var array
     * format [itemName => [childName => child]]
     */
    protected $children = [];

    /**
     * @var array
     * format [userId => [itemName => assignment]]
     */
    protected $assignments = [];

    /**
     * @var Rule[]
     * format [ruleName => rule]
     */
    protected $rules = [];

    /**
     * @var Menu[]
     */
    protected $menus = [];

    /**
     * @param RuleFactoryInterface $ruleFactory
     * @param CacheInterface       $cache               cache
     * @param LoggerInterface|null $logger
     * @param string|null          $itemCacheName       items cache name
     * @param string|null          $assignmentCacheName assignments cache name
     * @param string|null          $ruleCacheName       rules cache name
     * @param string|null          $menuCacheName
     */
    public function __construct(RuleFactoryInterface $ruleFactory,
        CacheInterface $cache,
        ?LoggerInterface $logger = null,
        ?string $itemCacheName = null,
        ?string $assignmentCacheName = null,
        ?string $ruleCacheName = null,
        ?string $menuCacheName = null)
    {
        parent::__construct($ruleFactory);
        $this->cache = $cache;
        $this->logger = $logger;
        $this->itemCacheName = $itemCacheName ?? 'auth:items';
        $this->assignmentCacheName = $assignmentCacheName ?? 'auth:assignments';
        $this->ruleCacheName = $ruleCacheName ?? 'auth.rules';
        $this->menuCacheName = $menuCacheName ?? 'auth.menus';
        $this->load();
    }

    /**
     * @param string $userId
     *
     * @return Assignment[]
     */
    public function getAssignments(string $userId): array
    {
        return $this->assignments[$userId] ?? [];
    }

    public function userHasPermission($userId, string $permissionName, array $parameters = []): bool
    {
        $assignments = $this->getAssignments($userId);

        if ($this->hasNoAssignments($assignments)) {
            return false;
        }

        /* @var $item Item */
        $item = $this->items[$permissionName] ?? null;

        if ($this->logger instanceof LoggerInterface) {
            $message = $item instanceof Role ? "Checking role: $permissionName" : "Checking permission: $permissionName";
            $this->logger->info(__METHOD__ . $message);
        }

        if (!$this->isPermission($item)) {
            return false;
        }

        return $this->userHasPermissionRecursive($userId, $permissionName, $parameters, $assignments);
    }

    /**
     * Performs access check for the specified user.
     * This method is internally called by [[checkAccess()]].
     *
     * @param string       $user        the user ID. This should br a string representing the unique identifier of a user.
     * @param string       $itemName    the name of the permission or role that need access check
     * @param array        $params      name-value pairs that would be passed to rules associated
     *                                  with the permissions and roles assigned to the user. A param with name 'user' is
     *                                  added to this array, which holds the value of `$userId`.
     * @param Assignment[] $assignments the assignments to the specified user
     *
     * @return bool whether the operations can be performed by the user.
     * @throws InvalidConfigException
     */
    protected function userHasPermissionRecursive(string $user,
        string $itemName,
        array $params,
        array $assignments): bool
    {
        if (!$this->hasItem($itemName)) {
            return false;
        }

        /* @var $item Item */
        $item = $this->items[$itemName];

        if ($this->logger instanceof LoggerInterface) {
            $message = $item instanceof Role ? "Checking role: $itemName" : "Checking permission: $itemName";
            $this->logger->info(__METHOD__ . $message);
        }

        if (!$this->executeRule($user, $item, $params)) {
            return false;
        }

        if (isset($assignments[$itemName])) {
            return true;
        }

        foreach ($this->children as $parentName => $children) {
            if (isset($children[$itemName]) && $this->userHasPermissionRecursive($user, $parentName, $params, $assignments)) {
                return true;
            }
        }

        return false;
    }

    public function canAddChild(Item $parent, Item $child): bool
    {
        if ($this->isPermission($parent) && $this->isRole($child)) {
            return false;
        }
        return !$this->detectLoop($parent, $child);
    }

    public function addChild(Item $parent, Item $child): void
    {
        if (!$this->hasItem($parent->getName()) || !$this->hasItem($child->getName())) {
            throw new InvalidArgumentException("Either \"{$parent->getName()}\" or \"{$child->getName()}\" does not exist.");
        }

        if ($parent->getName() === $child->getName()) {
            throw new InvalidArgumentException("Cannot add \"{$parent->getName()}\" as a child of itself.");
        }

        if ($this->isPermission($parent) && $this->isRole($child)) {
            throw new InvalidArgumentException("Can not add \"{$child->getName()}\" role as a child of \"{$parent->getName()}\" permission.");
        }

        if ($this->detectLoop($parent, $child)) {
            throw new InvalidCallException("Cannot add \"{$child->getName()}\" as a child of \"{$parent->getName()}\". A loop has been detected.");
        }

        if (isset($this->children[$parent->getName()][$child->getName()])) {
            throw new InvalidCallException("The item \"{$parent->getName()}\" already has a child \"{$child->getName()}\".");
        }

        $this->children[$parent->getName()][$child->getName()] = $this->items[$child->getName()];
        $this->saveItems();
    }

    /**
     * Checks whether there is a loop in the authorization item hierarchy.
     *
     * @param Item $parent parent item
     * @param Item $child  the child item that is to be added to the hierarchy
     *
     * @return bool whether a loop exists
     */
    protected function detectLoop(Item $parent, Item $child): bool
    {
        if ($child->getName() === $parent->getName()) {
            return true;
        }
        if (!isset($this->children[$child->getName()], $this->items[$parent->getName()])) {
            return false;
        }
        foreach ($this->children[$child->getName()] as $grandchild) {
            /* @var $grandchild Item */
            if ($this->detectLoop($parent, $grandchild)) {
                return true;
            }
        }

        return false;
    }

    public function removeChild(Item $parent, Item $child): void
    {
        if (isset($this->children[$parent->getName()][$child->getName()])) {
            unset($this->children[$parent->getName()][$child->getName()]);
            $this->saveItems();
        }
    }

    public function removeChildren(Item $parent): void
    {
        if (isset($this->children[$parent->getName()])) {
            unset($this->children[$parent->getName()]);
            $this->saveItems();
        }
    }

    public function hasChild(Item $parent, Item $child): bool
    {
        return isset($this->children[$parent->getName()][$child->getName()]);
    }

    public function assign(Item $item, string $userId): Assignment
    {
        $itemName = $this->getTypeByItem($item);

        if (!$this->hasItem($item->getName())) {
            throw new InvalidArgumentException("Unknown {$itemName} '{$item->getName()}'.");
        }

        if (isset($this->assignments[$userId][$item->getName()])) {
            throw new InvalidArgumentException("'{$item->getName()}' {$itemName} has already been assigned to user '$userId'.");
        }

        $this->assignments[$userId][$item->getName()] = new Assignment($userId, $item->getName(), time());
        $this->saveAssignments();

        return $this->assignments[$userId][$item->getName()];
    }

    public function revoke(Item $role, string $userId): void
    {
        if (isset($this->assignments[$userId][$role->getName()])) {
            unset($this->assignments[$userId][$role->getName()]);
            $this->saveAssignments();
        }
    }

    public function revokeAll(string $userId): void
    {
        if (isset($this->assignments[$userId]) && is_array($this->assignments[$userId])) {
            foreach ($this->assignments[$userId] as $itemName => $value) {
                unset($this->assignments[$userId][$itemName]);
            }
            $this->saveAssignments();
        }
    }

    public function getAssignment(string $roleName, string $userId): ?Assignment
    {
        return $this->assignments[$userId][$roleName] ?? null;
    }

    protected function getItems(string $type): array
    {
        $items = [];

        foreach ($this->items as $name => $item) {
            /* @var $item Item */
            if ($item->getType() === $type) {
                $items[$name] = $item;
            }
        }

        return $items;
    }

    protected function removeItem(Item $item): void
    {
        if ($this->hasItem($item->getName())) {
            foreach ($this->children as &$children) {
                unset($children[$item->getName()]);
            }
            unset($children);
            foreach ($this->assignments as &$assignments) {
                unset($assignments[$item->getName()]);
            }
            unset($assignments, $this->items[$item->getName()]);
            $this->saveItems();
            $this->saveAssignments();
        }
    }

    protected function getItem(string $name): ?Item
    {
        return $this->items[$name] ?? null;
    }

    protected function updateRule(string $name, Rule $rule): void
    {
        if ($rule->getName() !== $name) {
            unset($this->rules[$name]);
        }
        $this->rules[$rule->getName()] = $rule;
        $this->saveRules();
    }

    public function getRule(string $name): ?Rule
    {
        return $this->rules[$name] ?? null;
    }

    public function getRules(): array
    {
        return $this->rules;
    }

    public function getRolesByUser(string $userId): array
    {
        $roles = $this->getDefaultRoleInstances();
        foreach ($this->getAssignments($userId) as $name => $assignment) {
            $role = $this->items[$assignment->getItemName()];
            if ($role->getType() === Item::TYPE_ROLE) {
                $roles[$name] = $role;
            }
        }

        return $roles;
    }

    public function getChildRoles(string $roleName): array
    {
        $role = $this->getRole($roleName);

        if ($role === null) {
            throw new InvalidArgumentException("Role \"$roleName\" not found.");
        }

        $result = [];
        $this->getChildrenRecursive($roleName, $result);

        $roles = [$roleName => $role];

        $roles += array_filter($this->getRoles(), static function (Role $roleItem) use ($result) {
            return array_key_exists($roleItem->getName(), $result);
        });

        return $roles;
    }

    public function getPermissionsByRole(string $roleName): array
    {
        $result = [];
        $this->getChildrenRecursive($roleName, $result);

        if (empty($result)) {
            return [];
        }

        return $this->normalizePermissions($result);
    }

    /**
     * Recursively finds all children and grand children of the specified item.
     *
     * @param string $name   the name of the item whose children are to be looked for.
     * @param array  $result the children and grand children (in array keys)
     */
    protected function getChildrenRecursive(string $name, &$result): void
    {
        if (isset($this->children[$name])) {
            foreach ($this->children[$name] as $child) {
                $result[$child->getName()] = true;
                $this->getChildrenRecursive($child->getName(), $result);
            }
        }
    }

    public function getPermissionsByUser(string $userId): array
    {
        $directPermission = $this->getDirectPermissionsByUser($userId);
        $inheritedPermission = $this->getInheritedPermissionsByUser($userId);

        return array_merge($directPermission, $inheritedPermission);
    }

    /**
     * Returns all permissions that are directly assigned to user.
     *
     * @param string $userId the user ID (see [[\yii\web\User::id]])
     *
     * @return Permission[] all direct permissions that the user has. The array is indexed by the permission names.
     */
    protected function getDirectPermissionsByUser(string $userId): array
    {
        $permissions = [];
        foreach ($this->getAssignments($userId) as $name => $assignment) {
            $permission = $this->items[$assignment->getItemName()];
            if ($permission->getType() === Item::TYPE_PERMISSION) {
                $permissions[$name] = $permission;
            }
        }

        return $permissions;
    }

    /**
     * Returns all permissions that the user inherits from the roles assigned to him.
     *
     * @param string $userId the user ID (see [[\yii\web\User::id]])
     *
     * @return Permission[] all inherited permissions that the user has. The array is indexed by the permission names.
     */
    protected function getInheritedPermissionsByUser(string $userId): array
    {
        $assignments = $this->getAssignments($userId);
        $result = [];
        foreach (array_keys($assignments) as $roleName) {
            $this->getChildrenRecursive($roleName, $result);
        }

        if (empty($result)) {
            return [];
        }

        return $this->normalizePermissions($result);
    }

    public function getChildren(string $name): array
    {
        return $this->children[$name] ?? [];
    }

    public function removeAll(): void
    {
        $this->children = [];
        $this->items = [];
        $this->assignments = [];
        $this->rules = [];
        $this->save();
    }

    public function removeAllPermissions(): void
    {
        $this->removeAllItems(Item::TYPE_PERMISSION);
    }

    public function removeAllRoles(): void
    {
        $this->removeAllItems(Item::TYPE_ROLE);
    }

    /**
     * Removes all auth items of the specified type.
     *
     * @param string $type the auth item type (either Item::TYPE_PERMISSION or Item::TYPE_ROLE)
     */
    protected function removeAllItems(string $type): void
    {
        $names = [];
        foreach ($this->items as $name => $item) {
            if ($item->getType() === $type) {
                unset($this->items[$name]);
                $names[$name] = true;
            }
        }
        if (empty($names)) {
            return;
        }

        foreach ($this->assignments as $i => $assignments) {
            foreach ($assignments as $n => $assignment) {
                if (isset($names[$assignment->getItemName()])) {
                    unset($this->assignments[$i][$n]);
                }
            }
        }
        foreach ($this->children as $name => $children) {
            if (isset($names[$name])) {
                unset($this->children[$name]);
            } else {
                foreach ($children as $childName => $item) {
                    if (isset($names[$childName])) {
                        unset($children[$childName]);
                    }
                }
                $this->children[$name] = $children;
            }
        }

        $this->saveItems();
    }

    public function removeAllRules(): void
    {
        foreach ($this->items as &$item) {
            $item = $item->withRuleName(null);
        }
        unset($item);
        $this->rules = [];
        $this->saveRules();
    }

    public function removeAllAssignments(): void
    {
        $this->assignments = [];
        $this->saveAssignments();
    }

    protected function removeRule(Rule $rule): void
    {
        if (isset($this->rules[$rule->getName()])) {
            unset($this->rules[$rule->getName()]);
            foreach ($this->items as &$item) {
                if ($item->getRuleName() === $rule->getName()) {
                    $item = $item->withRuleName(null);
                }
            }
            unset($item);
            $this->saveRules();
        }
    }

    protected function addRule(Rule $rule): void
    {
        $this->rules[$rule->getName()] = $rule;
        $this->saveRules();
    }

    protected function updateItem(string $name, Item $item): void
    {
        if ($name !== $item->getName()) {
            if ($this->hasItem($item->getName())) {
                throw new InvalidArgumentException("Unable to change the item name. The name '{$item->getName()}' is already used by another item.");
            }

            // Remove old item in case of renaming
            unset($this->items[$name]);

            if (isset($this->children[$name])) {
                $this->children[$item->getName()] = $this->children[$name];
                unset($this->children[$name]);
            }
            foreach ($this->children as &$children) {
                if (isset($children[$name])) {
                    $children[$item->getName()] = $children[$name];
                    unset($children[$name]);
                }
            }
            unset($children);

            foreach ($this->assignments as &$assignments) {
                if (isset($assignments[$name])) {
                    $assignments[$item->getName()] = $assignments[$name]->withItemName($item->getName());
                    unset($assignments[$name]);
                }
            }
            unset($assignments);

            $this->saveAssignments();
        }

        $this->items[$item->getName()] = $item;

        $this->saveItems();
    }

    protected function addItem(Item $item): void
    {
        $time = time();
        if (!$item->hasCreatedAt()) {
            $item = $item->withCreatedAt($time);
        }
        if (!$item->hasUpdatedAt()) {
            $item = $item->withUpdatedAt($time);
        }

        $this->items[$item->getName()] = $item;

        $this->saveItems();
    }

    /**
     * Loads authorization data from persistent storage.
     */
    protected function load(): void
    {
        $this->children = [];
        $this->rules = [];
        $this->assignments = [];
        $this->items = [];
        $this->menus = [];

        $items = $this->cache->get($this->itemCacheName, []);
        $assignments = $this->cache->get($this->assignmentCacheName, []);
        $rules = $this->cache->get($this->ruleCacheName, []);
        $menus = $this->cache->get($this->menuCacheName, []);

        foreach ($items as $name => $item) {
            $class = $item['type'] === Item::TYPE_PERMISSION ? Permission::class : Role::class;
            $this->items[$name] = (new $class($name))->withDescription($item['description'] ?? '')
                ->withRuleName($item['ruleName'] ?? null)
                ->withCreatedAt($item['createdAt'])
                ->withUpdatedAt($item['updatedAt']);

            if (isset($item['children'])) {
                foreach ($item['children'] as $childName) {
                    if ($this->hasItem($childName)) {
                        $this->children[$name][$childName] = $this->items[$childName];
                    }
                }
            }
        }

        $time = time();
        foreach ($assignments as $userId => $roles) {
            foreach ($roles as $role) {
                $this->assignments[$userId][$role] = new Assignment((string)$userId, $role, $time);
            }
        }

        foreach ($rules as $name => $ruleData) {
            $this->rules[$name] = unserialize($ruleData);
        }

        foreach ($menus as $name => $menu) {
            $this->menus[$name] = $this->populateMenu($menu);
        }

    }

    public function populateMenu($row): Menu
    {
        return (new Menu($row['name']))->withPid($row['pid'])
            ->withIcon($row['icon'])
            ->withPath($row['path'])
            ->withSort($row['sort'])
            ->withTemplate($row['template'])
            ->withRole($row['role'])
            ->withCreatedAt($row['created_at'])
            ->withUpdatedAt($row['updated_at']);
    }

    /**
     * Saves authorization data into persistent storage.
     */
    protected function save(): void
    {
        $this->saveItems();
        $this->saveAssignments();
        $this->saveRules();
    }

    /**
     * Saves items data into persistent storage.
     */
    protected function saveItems(): void
    {
        $items = [];
        foreach ($this->items as $name => $item) {
            /* @var $item Item */
            $items[$name] = array_filter($item->getAttributes());
            if (isset($this->children[$name])) {
                foreach ($this->children[$name] as $child) {
                    /* @var $child Item */
                    $items[$name]['children'][] = $child->getName();
                }
            }
        }
        $this->cache->set($this->itemCacheName, $items);
    }

    protected function saveMenus(): void
    {
        $items = [];
        foreach ($this->menus as $name => $item) {
            $items[$name] = array_filter($item->getAttributes());
        }
        $this->cache->set($this->menuCacheName, $items);
    }

    /**
     * Saves assignments data into persistent storage.
     */
    protected function saveAssignments(): void
    {
        $assignmentData = [];
        foreach ($this->assignments as $userId => $assignments) {
            foreach ($assignments as $assignment) {
                /* @var $assignment Assignment */
                $assignmentData[$userId][] = $assignment->getItemName();
            }
        }
        $this->cache->set($this->assignmentCacheName, $assignmentData);
    }

    /**
     * Saves rules data into persistent storage.
     */
    protected function saveRules(): void
    {
        $rules = [];
        foreach ($this->rules as $name => $rule) {
            $rules[$name] = serialize($rule);
        }
        $this->cache->set($this->ruleCacheName, $rules);
    }

    public function getUserIdsByRole(string $roleName): array
    {
        $result = [];
        foreach ($this->assignments as $userID => $assignments) {
            $userID = (string)$userID;
            foreach ($assignments as $userAssignment) {
                if ($userAssignment->getItemName() === $roleName && $userAssignment->getUserId() === $userID) {
                    $result[] = $userID;
                }
            }
        }

        return $result;
    }

    protected function getTypeByItem(Item $item): string
    {
        if ($this->isRole($item) || $this->isPermission($item)) {
            return $item->getType();
        }

        return 'authorization item';
    }

    protected function hasItem(string $name): bool
    {
        return isset($this->items[$name]);
    }

    protected function normalizePermissions(array $permissions): array
    {
        $normalizePermissions = [];
        foreach (array_keys($permissions) as $itemName) {
            if ($this->hasItem($itemName) && $this->isPermission($this->items[$itemName])) {
                $normalizePermissions[$itemName] = $this->items[$itemName];
            }
        }

        return $normalizePermissions;
    }

    protected function addMenu(Menu $menu): void
    {
        $time = time();
        $menu = $menu->withUpdatedAt($time)->withCreatedAt($time);
        $this->menus[$menu->getName()] = $menu;

        $this->saveMenus();
    }

    protected function removeMenu(Menu $menu): void
    {
        if (isset($this->menus[$menu->getName()])) {
            unset($this->menus[$menu->getName()]);
            $this->saveMenus();
        }
    }

    protected function updateMenu(string $name, Menu $menu): void
    {
        if ($menu->getName() !== $name) {
            unset($this->menus[$name]);
        }
        $this->menus[$menu->getName()] = $menu;
        $this->saveMenus();
    }

    public function getMenu(string $name): ?Menu
    {
        return $this->menus[$name] ?? null;
    }

    public function getMenus(string $role = ''): array
    {
        $items = [];
        foreach ($this->menus as $name => $item) {
            if (!empty($role)) {
                if ($item->getRole() === $role) {
                    $items[$name] = $item;
                }
            } else {
                $items[$name] = $item;
            }
        }
        return $items;
    }
}
