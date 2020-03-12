<?php

namespace Lengbin\YiiDb\Rbac\Manager;

use Lengbin\YiiDb\Rbac\Assignment;
use Lengbin\YiiDb\Rbac\Exceptions\InvalidArgumentException;
use Lengbin\YiiDb\Rbac\Exceptions\InvalidCallException;
use Lengbin\YiiDb\Rbac\Item;
use Lengbin\YiiDb\Rbac\Permission;
use Lengbin\YiiDb\Rbac\Role;
use Lengbin\YiiDb\Rbac\Rule;
use Lengbin\YiiDb\Rbac\RuleFactoryInterface;
use Lengbin\YiiDb\ConnectionInterface;
use Lengbin\YiiDb\Expression;
use Lengbin\YiiDb\Query;
use Psr\Log\LoggerInterface;
use Psr\SimpleCache\CacheInterface;

class DbManager extends BaseManager
{
    /**
     * @var ConnectionInterface
     */
    protected $db;

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
     * @var string the name of the table storing authorization items. Defaults to "auth_item".
     */
    protected $itemTable;
    /**
     * @var string the name of the table storing authorization item hierarchy. Defaults to "auth_item_child".
     */
    protected $itemChildTable;
    /**
     * @var string the name of the table storing authorization item assignments. Defaults to "auth_assignment".
     */
    protected $assignmentTable;
    /**
     * @var string the name of the table storing rules. Defaults to "auth_rule".
     */
    protected $ruleTable;

    /**
     * 缓存key
     * @var string
     */
    public $cacheKey = 'rbac:db';

    /**
     * @var Item[]
     * format [itemName => item]
     */
    protected $items = [];

    /**
     * @var Rule[]
     * format [ruleName => rule]
     */
    protected $rules = [];

    /**
     * @var array auth item parent-child relationships (childName => list of parents)
     */
    protected $parents = [];

    /**
     * @var array
     */
    private $_checkAccessAssignments = [];

    /**
     * DbManager constructor.
     *
     * @param RuleFactoryInterface $ruleFactory
     * @param ConnectionInterface  $db
     * @param string|null          $itemTable
     * @param string|null          $itemChildTable
     * @param string|null          $assignmentTable
     * @param string|null          $ruleTable
     * @param CacheInterface|null  $cache
     * @param LoggerInterface|null $logger
     *
     */
    public function __construct(RuleFactoryInterface $ruleFactory,
        ConnectionInterface $db,
        ?CacheInterface $cache = null,
        ?LoggerInterface $logger = null,
        ?string $itemTable = null,
        ?string $itemChildTable = null,
        ?string $assignmentTable = null,
        ?string $ruleTable = null)
    {
        parent::__construct($ruleFactory);
        $this->cache = $cache;
        $this->db = $db;
        $this->logger = $logger;
        $this->itemTable = $itemTable ?? '{{%auth_item}}';
        $this->itemChildTable = $itemChildTable ?? '{{%auth_item_child}}';
        $this->assignmentTable = $assignmentTable ?? '{{%auth_assignment}}';
        $this->ruleTable = $ruleTable ?? '{{%auth_rule}}';
    }

    /**
     * load cache
     */
    protected function loadFromCache(): void
    {
        if (!empty($this->items) || !$this->cache instanceof CacheInterface) {
            return;
        }

        $data = $this->cache->get($this->cacheKey);
        if (is_array($data) && isset($data[0], $data[1], $data[2])) {
            [$this->items, $this->rules, $this->parents] = $data;
            return;
        }

        $query = (new Query())->from($this->itemTable);
        $this->items = [];
        foreach ($query->all($this->db) as $row) {
            $this->items[$row['name']] = $this->populateItem($row);
        }

        $this->rules = $this->getRules();

        $this->parents = [];
        $query = (new Query())->from($this->itemChildTable);
        foreach ($query->all($this->db) as $row) {
            if (isset($this->items[$row['child']])) {
                $this->parents[$row['child']][] = $row['parent'];
            }
        }

        $this->cache->set($this->cacheKey, [$this->items, $this->rules, $this->parents]);
    }

    protected function userHasPermissionRecursiveFromCache(string $user, string $itemName, array $params, array $assignments): bool
    {
        if (!isset($this->items[$itemName])) {
            return false;
        }

        $item = $this->items[$itemName];

        if ($this->logger instanceof LoggerInterface) {
            $message = $item instanceof Role ? "Checking role: $itemName" : "Checking permission: $itemName";
            $this->logger->debug(__METHOD__ . $message);
        }

        if (!$this->executeRule($user, $item, $params)) {
            return false;
        }

        if (isset($assignments[$itemName]) || in_array($itemName, $this->defaultRoles)) {
            return true;
        }

        if (!empty($this->parents[$itemName])) {
            foreach ($this->parents[$itemName] as $parent) {
                if ($this->userHasPermissionRecursiveFromCache($user, $parent, $params, $assignments)) {
                    return true;
                }
            }
        }

        return false;
    }

    protected function userHasPermissionRecursive(string $user, string $itemName, array $params, array $assignments): bool
    {
        $item = $this->getItem($itemName);
        if ($item === null) {
            return false;
        }

        if ($this->logger instanceof LoggerInterface) {
            $message = $item instanceof Role ? "Checking role: $itemName" : "Checking permission: $itemName";
            $this->logger->debug(__METHOD__ . $message);
        }

        if (!$this->executeRule($user, $item, $params)) {
            return false;
        }

        if (isset($assignments[$itemName]) || in_array($itemName, $this->defaultRoles)) {
            return true;
        }

        $query = new Query();
        $parents = $query->select(['parent'])->from($this->itemChildTable)->where(['child' => $itemName])->column($this->db);
        foreach ($parents as $parent) {
            if ($this->userHasPermissionRecursive($user, $parent, $params, $assignments)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @inheritDoc
     */
    public function userHasPermission($userId, string $permissionName, array $parameters = []): bool
    {
        if (isset($this->_checkAccessAssignments[(string)$userId])) {
            $assignments = $this->_checkAccessAssignments[(string)$userId];
        } else {
            $assignments = $this->getAssignments($userId);
            $this->_checkAccessAssignments[(string)$userId] = $assignments;
        }

        if ($this->hasNoAssignments($assignments)) {
            return false;
        }

        $this->loadFromCache();

        if (!empty($this->items)) {
            return $this->userHasPermissionRecursiveFromCache($userId, $permissionName, $parameters, $assignments);
        }

        return $this->userHasPermissionRecursive($userId, $permissionName, $parameters, $assignments);

        /**
         *
         *
         * $this->loadFromCache();
         * if ($this->items !== null) {
         * return $this->checkAccessFromCache($userId, $permissionName, $params, $assignments);
         * }
         *
         * return $this->checkAccessRecursive($userId, $permissionName, $params, $assignments);
         */
    }

    /**
     * 格式化
     *
     * @param $row
     *
     * @return mixed
     */
    protected function populateItem($row): Item
    {
        $class = $row['type'] === Item::TYPE_PERMISSION ? Permission::class : Role::class;

        return (new $class($row['name']))->withDescription($row['description'] ?? '')
            ->withRuleName($row['rule_name'] ?? null)
            ->withCreatedAt($row['created_at'])
            ->withUpdatedAt($row['updated_at']);
    }

    /**
     * 名称是否为空
     *
     * @param string $name
     *
     * @return bool
     */
    protected function isEmptyName(string $name): bool
    {
        return !isset($name) || $name === '';
    }

    /**
     * user id是否为空
     *
     * @param string $userId
     *
     * @return bool
     */
    protected function isEmptyUserId(string $userId): bool
    {
        return !isset($userId) || $userId === '';
    }

    /**
     * @param string $name
     *
     * @return Item|null
     * @throws \Lengbin\YiiDb\Exception\Exception
     * @throws \Lengbin\YiiDb\Exception\InvalidConfigException
     * @throws \Lengbin\YiiDb\Exception\NotSupportedException
     * @throws \Psr\SimpleCache\InvalidArgumentException
     * @throws \Throwable
     */
    protected function getItem(string $name): ?Item
    {
        if ($this->isEmptyName($name)) {
            return null;
        }

        if (!empty($this->items[$name])) {
            return $this->items[$name];
        }

        $row = (new Query())->from($this->itemTable)->where(['name' => $name])->one($this->db);

        if ($row === false) {
            return null;
        }

        return $this->populateItem($row);
    }

    /**
     * @inheritDoc
     */
    protected function getItems(string $type): array
    {
        $query = (new Query())->from($this->itemTable)->where(['type' => $type]);

        $items = [];
        foreach ($query->all($this->db) as $row) {
            $items[$row['name']] = $this->populateItem($row);
        }

        return $items;
    }

    protected function cleanCache(): void
    {
        if ($this->cache !== null) {
            $this->cache->delete($this->cacheKey);
            $this->items = [];
            $this->rules = [];
            $this->parents = [];
        }
        $this->_checkAccessAssignments = [];
    }

    /**
     * @inheritDoc
     */
    protected function addItem(Item $item): void
    {
        $time = time();
        $item = $item->withCreatedAt($time)->withUpdatedAt($time);
        $this->db->createCommand()->insert($this->itemTable, $item->getAttributes())->execute();
        $this->cleanCache();
    }

    /**
     * @inheritDoc
     */
    protected function addRule(Rule $rule): void
    {
        $time = time();
        $data = $rule->withCreatedAt($time)->withUpdatedAt($time)->getAttributes();
        $data['data'] = serialize($rule);
        $this->db->createCommand()->insert($this->ruleTable, $data)->execute();
        $this->cleanCache();
    }

    /**
     * @inheritDoc
     */
    protected function removeItem(Item $item): void
    {
        $this->db->createCommand()->delete($this->itemTable, ['name' => $item->getName()])->execute();
        $this->cleanCache();
    }

    /**
     * @inheritDoc
     */
    protected function removeRule(Rule $rule): void
    {
        $this->db->createCommand()->delete($this->ruleTable, ['name' => $rule->getName()])->execute();
        $this->cleanCache();
    }

    /**
     * @inheritDoc
     */
    protected function updateItem(string $name, Item $item): void
    {
        $item = $item->withUpdatedAt(time());
        $this->db->createCommand()->update($this->itemTable, $item->getAttributes(), ['name' => $name,])->execute();
        $this->cleanCache();
    }

    /**
     * @inheritDoc
     */
    protected function updateRule(string $name, Rule $rule): void
    {
        $rule = $rule->withUpdatedAt(time());
        $this->db->createCommand()->update($this->ruleTable, $rule->getAttributes(), ['name' => $name,])->execute();
        $this->cleanCache();
    }

    /**
     * @inheritDoc
     */
    public function getRolesByUser(string $userId): array
    {
        if ($this->isEmptyUserId($userId)) {
            return [];
        }

        $query = (new Query())->select('b.*')
            ->from(['a' => $this->assignmentTable, 'b' => $this->itemTable])
            ->where('{{a}}.[[item_name]]={{b}}.[[name]]')
            ->andWhere(['a.user_id' => (string)$userId])
            ->andWhere(['b.type' => Item::TYPE_ROLE]);

        $roles = $this->getDefaultRoleInstances();
        foreach ($query->all($this->db) as $row) {
            $roles[$row['name']] = $this->populateItem($row);
        }

        return $roles;
    }

    /**
     * Recursively finds all children and grand children of the specified item.
     *
     * @param string $name   the name of the item whose children are to be looked for.
     * @param array  $result the children and grand children (in array keys)
     */
    protected function getChildrenRecursive($name, $childrenList, &$result): void
    {
        if (isset($childrenList[$name])) {
            foreach ($childrenList[$name] as $child) {
                $result[$child] = true;
                $this->getChildrenRecursive($child, $childrenList, $result);
            }
        }
    }

    /**
     * @return array
     * @throws \Lengbin\YiiDb\Exception\Exception
     * @throws \Lengbin\YiiDb\Exception\InvalidConfigException
     * @throws \Lengbin\YiiDb\Exception\NotSupportedException
     * @throws \Psr\SimpleCache\InvalidArgumentException
     * @throws \Throwable
     */
    protected function getChildrenList(): array
    {
        $query = (new Query())->from($this->itemChildTable);
        $parents = [];
        foreach ($query->all($this->db) as $row) {
            $parents[$row['parent']][] = $row['child'];
        }

        return $parents;
    }

    /**
     * @inheritDoc
     */
    public function getChildRoles(string $roleName): array
    {
        $role = $this->getRole($roleName);

        if ($role === null) {
            throw new InvalidArgumentException("Role \"$roleName\" not found.");
        }

        $result = [];
        $this->getChildrenRecursive($roleName, $this->getChildrenList(), $result);

        $roles = [$roleName => $role];

        $roles += array_filter($this->getRoles(), static function (Role $roleItem) use ($result) {
            return array_key_exists($roleItem->getName(), $result);
        });

        return $roles;
    }

    protected function getPermissionsByNames($result): array
    {
        if (empty($result)) {
            return [];
        }

        $query = (new Query())->from($this->itemTable)->where([
            'type' => Item::TYPE_PERMISSION,
            'name' => array_keys($result),
        ]);
        $permissions = [];
        foreach ($query->all($this->db) as $row) {
            $permissions[$row['name']] = $this->populateItem($row);
        }

        return $permissions;
    }

    /**
     * @inheritDoc
     */
    public function getPermissionsByRole(string $roleName): array
    {
        $result = [];
        $this->getChildrenRecursive($roleName, $this->getChildrenList(), $result);
        return $this->getPermissionsByNames($result);
    }

    protected function getDirectPermissionsByUser(string $userId): array
    {
        $query = (new Query())->select('b.*')
            ->from(['a' => $this->assignmentTable, 'b' => $this->itemTable])
            ->where('{{a}}.[[item_name]]={{b}}.[[name]]')
            ->andWhere(['a.user_id' => (string)$userId])
            ->andWhere(['b.type' => Item::TYPE_PERMISSION]);

        $permissions = [];
        foreach ($query->all($this->db) as $row) {
            $permissions[$row['name']] = $this->populateItem($row);
        }

        return $permissions;
    }

    protected function getInheritedPermissionsByUser(string $userId): array
    {
        $query = (new Query())->select('item_name')->from($this->assignmentTable)->where(['user_id' => (string)$userId]);

        $childrenList = $this->getChildrenList();
        $result = [];
        foreach ($query->column($this->db) as $roleName) {
            $this->getChildrenRecursive($roleName, $childrenList, $result);
        }
        return $this->getPermissionsByNames($result);
    }

    /**
     * @inheritDoc
     */
    public function getPermissionsByUser(string $userId): array
    {
        if ($this->isEmptyUserId($userId)) {
            return [];
        }

        $directPermission = $this->getDirectPermissionsByUser($userId);
        $inheritedPermission = $this->getInheritedPermissionsByUser($userId);

        return array_merge($directPermission, $inheritedPermission);
    }

    /**
     * @inheritDoc
     */
    public function getRule(string $name): ?Rule
    {
        if (!empty($this->rules[$name])) {
            return $this->rules[$name];
        }

        $row = (new Query())->select(['data'])->from($this->ruleTable)->where(['name' => $name])->one($this->db);
        if ($row === false || empty($row['data'])) {
            return null;
        }
        $data = $row['data'];
        if (is_resource($data)) {
            $data = stream_get_contents($data);
        }

        return unserialize($data);
    }

    /**
     * @inheritDoc
     */
    public function getRules(): array
    {
        if (!empty($this->rules)) {
            return $this->rules;
        }

        $query = (new Query())->from($this->ruleTable);

        $rules = [];
        foreach ($query->all($this->db) as $row) {
            $data = $row['data'];
            if (is_resource($data)) {
                $data = stream_get_contents($data);
            }
            $rules[$row['name']] = unserialize($data);
        }

        return $rules;
    }

    protected function detectLoop(Item $parent, Item $child)
    {
        if ($child->getName() === $parent->getName()) {
            return true;
        }
        foreach ($this->getChildren($child->getName()) as $grandchild) {
            if ($this->detectLoop($parent, $grandchild)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @inheritDoc
     */
    public function canAddChild(Item $parent, Item $child): bool
    {
        return !$this->detectLoop($parent, $child);
    }

    /**
     * @inheritDoc
     */
    public function addChild(Item $parent, Item $child): void
    {
        if ($parent->getName() === $child->getName()) {
            throw new InvalidArgumentException("Cannot add \"{$parent->getName()}\" as a child of itself.");
        }

        if ($this->isPermission($parent) && $this->isRole($child)) {
            throw new InvalidArgumentException("Can not add \"{$child->getName()}\" role as a child of \"{$parent->getName()}\" permission.");
        }

        if ($this->detectLoop($parent, $child)) {
            throw new InvalidCallException("Cannot add \"{$child->getName()}\" as a child of \"{$parent->getName()}\". A loop has been detected.");
        }

        $this->db->createCommand()->insert($this->itemChildTable, ['parent' => $parent->getName(), 'child' => $child->getName()])->execute();

        $this->cleanCache();
    }

    /**
     * @inheritDoc
     */
    public function removeChild(Item $parent, Item $child): void
    {
        $this->db->createCommand()->delete($this->itemChildTable, ['parent' => $parent->getName(), 'child' => $child->getName()])->execute();
        $this->cleanCache();
    }

    /**
     * @inheritDoc
     */
    public function removeChildren(Item $parent): void
    {
        $this->db->createCommand()->delete($this->itemChildTable, ['parent' => $parent->getName()])->execute();
        $this->cleanCache();
    }

    /**
     * @inheritDoc
     */
    public function hasChild(Item $parent, Item $child): bool
    {
        return (new Query())->from($this->itemChildTable)->where(['parent' => $parent->getName(), 'child' => $child->getName()])->one($this->db) !== false;
    }

    /**
     * @inheritDoc
     */
    public function getChildren(string $name): array
    {
        $query = (new Query())->select(['name', 'type', 'description', 'rule_name', 'created_at', 'updated_at'])->from([
            $this->itemTable,
            $this->itemChildTable,
        ])->where(['parent' => $name, 'name' => new Expression('child')]);

        $children = [];
        foreach ($query->all($this->db) as $row) {
            $children[$row['name']] = $this->populateItem($row);
        }

        return $children;
    }

    protected function getTypeByItem(Item $item): string
    {
        if ($this->isRole($item) || $this->isPermission($item)) {
            return $item->getType();
        }

        return 'authorization item';
    }

    /**
     * @inheritDoc
     */
    public function assign(Item $item, string $userId): Assignment
    {
        $assignment = new Assignment($userId, $item->getName(), time());
        $this->db->createCommand()->insert($this->assignmentTable, $assignment->getAttributes())->execute();
        unset($this->_checkAccessAssignments[(string)$userId]);
        return $assignment;
    }

    /**
     * @inheritDoc
     */
    public function revoke(Item $item, string $userId): void
    {
        if ($this->isEmptyUserId($userId)) {
            return;
        }
        unset($this->_checkAccessAssignments[(string)$userId]);
        $this->db->createCommand()->delete($this->assignmentTable, ['user_id' => (string)$userId, 'item_name' => $item->getName()])->execute();
    }

    /**
     * @inheritDoc
     */
    public function revokeAll(string $userId): void
    {
        if ($this->isEmptyUserId($userId)) {
            return;
        }
        unset($this->_checkAccessAssignments[(string)$userId]);
        $this->db->createCommand()->delete($this->assignmentTable, ['user_id' => (string)$userId])->execute();
    }

    /**
     * @inheritDoc
     */
    public function getAssignment(string $itemName, string $userId): ?Assignment
    {
        if ($this->isEmptyUserId($userId)) {
            return null;
        }

        $row = (new Query())->from($this->assignmentTable)->where(['user_id' => (string)$userId, 'item_name' => $itemName])->one($this->db);

        if ($row === false) {
            return null;
        }

        return new Assignment($row['user_id'], $row['item_name'], $row['created_at']);
    }

    /**
     * @inheritDoc
     */
    public function getAssignments(string $userId): array
    {
        if ($this->isEmptyUserId($userId)) {
            return [];
        }

        $query = (new Query())->from($this->assignmentTable)->where(['user_id' => (string)$userId]);

        $assignments = [];
        foreach ($query->all($this->db) as $row) {
            $assignments[$row['item_name']] = new Assignment($row['user_id'], $row['item_name'], $row['created_at']);
        }

        return $assignments;
    }

    /**
     * @inheritDoc
     */
    public function getUserIdsByRole(string $roleName): array
    {
        if ($this->isEmptyName($roleName)) {
            return [];
        }
        return (new Query())->select('user_id')->from($this->assignmentTable)->where(['item_name' => $roleName])->column($this->db);
    }

    /**
     * @inheritDoc
     */
    public function removeAll(): void
    {
        $this->removeAllAssignments();
        $this->db->createCommand()->delete($this->itemChildTable)->execute();
        $this->db->createCommand()->delete($this->itemTable)->execute();
        $this->removeAllRules();
        $this->cleanCache();
    }

    /**
     * @inheritDoc
     */
    public function removeAllPermissions(): void
    {
        $this->db->createCommand()->delete($this->itemTable, ['type' => Item::TYPE_PERMISSION])->execute();
        $this->cleanCache();
    }

    /**
     * @inheritDoc
     */
    public function removeAllRoles(): void
    {
        $this->db->createCommand()->delete($this->itemTable, ['type' => Item::TYPE_ROLE])->execute();
        $this->cleanCache();
    }

    /**
     * @inheritDoc
     */
    public function removeAllRules(): void
    {
        $this->db->createCommand()->delete($this->ruleTable)->execute();
    }

    /**
     * @inheritDoc
     */
    public function removeAllAssignments(): void
    {
        $this->_checkAccessAssignments = [];
        $this->db->createCommand()->delete($this->assignmentTable)->execute();
    }
}
