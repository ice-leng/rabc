<?php

namespace Lengbin\YiiSoft\Rbac\Manager;

use Lengbin\YiiSoft\Rbac\Assignment;
use Lengbin\YiiSoft\Rbac\ConnectionInterface;
use Lengbin\YiiSoft\Rbac\Exceptions\InvalidArgumentException;
use Lengbin\YiiSoft\Rbac\Exceptions\InvalidCallException;
use Lengbin\YiiSoft\Rbac\Item;
use Lengbin\YiiSoft\Rbac\Menu;
use Lengbin\YiiSoft\Rbac\Permission;
use Lengbin\YiiSoft\Rbac\Role;
use Lengbin\YiiSoft\Rbac\Rule;
use Lengbin\YiiSoft\Rbac\RuleFactoryInterface;
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
     * @var string
     */
    protected $menuTable;

    /**
     * 缓存key
     * @var string
     */
    public $cacheKey = 'auth:db';

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
     * @var Menu[]
     * format [menuName => Menu]
     */
    protected $menus = [];

    /**
     * @var array
     */
    private $_checkAccessAssignments = [];

    /**
     * DbManager constructor.
     *
     * @param RuleFactoryInterface $ruleFactory
     * @param ConnectionInterface  $db
     * @param CacheInterface|null  $cache
     * @param LoggerInterface|null $logger
     * @param string|null          $itemTable
     * @param string|null          $itemChildTable
     * @param string|null          $assignmentTable
     * @param string|null          $ruleTable
     * @param string|null          $menuTable
     */
    public function __construct(RuleFactoryInterface $ruleFactory,
        ConnectionInterface $db,
        ?CacheInterface $cache = null,
        ?LoggerInterface $logger = null,
        ?string $itemTable = null,
        ?string $itemChildTable = null,
        ?string $assignmentTable = null,
        ?string $ruleTable = null,
        ?string $menuTable = null)
    {
        parent::__construct($ruleFactory);
        $this->cache = $cache;
        $this->db = $db;
        $this->logger = $logger;
        $this->itemTable = $itemTable ?? 'auth_item';
        $this->itemChildTable = $itemChildTable ?? 'auth_item_child';
        $this->assignmentTable = $assignmentTable ?? 'auth_assignment';
        $this->ruleTable = $ruleTable ?? 'auth_rule';
        $this->menuTable = $menuTable ?? 'auth_menu';
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
        if (is_array($data) && isset($data[0], $data[1], $data[2], $data[3])) {
            [$this->items, $this->rules, $this->parents] = $data;
            return;
        }

        $items = $this->db->select("SELECT * FROM {$this->itemTable}");
        $this->items = [];
        foreach ($items as $row) {
            $result = $this->populateItem($row);
            $this->items[$result->getName()] = $result;
        }

        $this->rules = $this->getRules();

        $this->parents = [];

        $itemChildren = $this->db->select("SELECT * FROM {$this->itemChildTable}");

        foreach ($itemChildren as $row) {
            $row = (array)$row;
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
            $this->logger->info(__METHOD__ . $message);
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

        $parents = $this->db->select("SELECT parent FROM {$this->itemChildTable} WHERE child = :child", [':child' => $itemName]);
        $parents = !empty($parents) ? array_column($parents, 'parent') : [];
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
    }

    /**
     * 格式化
     *
     * @param $row
     *
     * @return mixed
     */
    public function populateItem($row): Item
    {
        $row = (array)$row;
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

        $row = $this->db->selectOne("SELECT * FROM {$this->itemTable} WHERE name = :name LIMIT 1", [':name' => $name]);

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
        $rows = $this->db->select("SELECT * FROM {$this->itemTable} WHERE type = :type", [':type' => $type]);
        $items = [];
        foreach ($rows as $row) {
            $item = $this->populateItem($row);
            $items[$item->getName()] = $item;
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
            $this->menus = [];
        }
        $this->_checkAccessAssignments = [];
    }

    /**
     * 添加
     *
     * @param string $tableName
     * @param array  $data ['id' => 1]
     *
     * @return int
     */
    protected function insertData(string $tableName, array $data)
    {
        $params = [];
        $fields = array_keys($data);
        $filed = implode('`, `', $fields);
        $sql = 'INSERT INTO ' . $tableName . ' (`' . $filed . '`) VALUES (';
        foreach ($data as $n => $d) {
            $name = ':' . $n;
            $sql .= $name . ', ';
            $params[$name] = $d;
        }
        $sql = substr($sql, 0, strripos($sql, ', '));
        $sql .= ')';
        return $this->db->insert($sql, $params);
    }

    /**
     * 更新
     *
     * @param string $tableName
     * @param array  $data  ['name' => 1]
     * @param array  $where ['id' => 1]
     *
     * @return mixed
     */
    protected function updateData(string $tableName, array $data, array $where = [])
    {
        $params = [];
        $sql = "UPDATE `{$tableName}` SET ";

        foreach ($data as $n => $d) {
            if (is_null($d)) {
                continue;
            }
            $n2 = ':p' . $n;
            $params[$n2] = $d;
            $sql .= "{$n} = {$n2}, ";
        }
        $sql = substr($sql, 0, strripos($sql, ', '));
        $sql .= ' WHERE ';

        foreach ($where as $n => $d) {
            if (is_null($d)) {
                continue;
            }
            $n2 = ':w' . $n;
            $params[$n2] = $d;
            $sql .= "{$n} = {$n2} AND ";
        }
        $sql = substr($sql, 0, strripos($sql, 'AND '));
        return $this->db->update($sql, $params);
    }

    /**
     * @param string $tableName
     * @param array  $where
     *
     * @return int
     */
    protected function deleteData(string $tableName, array $where = [])
    {
        $params = [];
        $sql = "DELETE FROM `{$tableName}`";
        if (!empty($where)) {
            $sql .= ' WHERE ';
            foreach ($where as $n => $d) {
                if (is_null($d)) {
                    continue;
                }
                $n2 = ':' . $n;
                $params[$n2] = $d;
                $sql .= "{$n} = {$n2} AND ";
            }
            $sql = substr($sql, 0, strripos($sql, 'AND '));
        }
        return $this->db->delete($sql, $params);
    }

    /**
     * @inheritDoc
     */
    protected function addItem(Item $item): void
    {
        $time = time();
        $item = $item->withCreatedAt($time)->withUpdatedAt($time);
        $this->insertData($this->itemTable, $item->getAttributes());
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
        $this->insertData($this->ruleTable, $data);
        $this->cleanCache();
    }

    /**
     * @inheritDoc
     */
    protected function removeItem(Item $item): void
    {
        $this->deleteData($this->itemTable, ['name' => $item->getName()]);
        $this->cleanCache();
    }

    /**
     * @inheritDoc
     */
    protected function removeRule(Rule $rule): void
    {
        $this->deleteData($this->ruleTable, ['name' => $rule->getName()]);
        $this->cleanCache();
    }

    /**
     * @inheritDoc
     */
    protected function updateItem(string $name, Item $item): void
    {
        $item = $item->withUpdatedAt(time());
        $this->updateData($this->itemTable, $item->getAttributes(), ['name' => $name,]);
        $this->cleanCache();
    }

    /**
     * @inheritDoc
     */
    protected function updateRule(string $name, Rule $rule): void
    {
        $rule = $rule->withUpdatedAt(time());
        $this->updateData($this->ruleTable, $rule->getAttributes(), ['name' => $name,]);
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

        $sql = "SELECT b.* FROM {$this->assignmentTable} as a INNER JOIN {$this->itemTable} as b on a.item_name = b.name WHERE a.user_id = :user_id and b.type = :type";
        $rows = $this->db->select($sql, [':type' => Item::TYPE_ROLE, ':user_id' => $userId]);
        $roles = $this->getDefaultRoleInstances();
        foreach ($rows as $row) {
            $item = $this->populateItem($row);
            $roles[$item->getName()] = $item;
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
     */
    protected function getChildrenList(): array
    {
        $rows = $this->db->select("SELECT * FROM {$this->itemChildTable}");
        $parents = [];
        foreach ($rows as $row) {
            $row = (array)$row;
            $parents[$row['parent']][] = $row['child'];
        }

        return $parents;
    }

    /**
     * @return array
     */
    public function getParentPermissions(): array
    {
        return $this->getChildrenListByType(Item::TYPE_PERMISSION);
    }

    /**
     * @return array
     */
    public function getParentRoles(): array
    {
        return $this->getChildrenListByType(Item::TYPE_ROLE);
    }

    /**
     * @param string $type
     *
     * @return array
     */
    protected function getChildrenListByType(string $type): array
    {
        $sql = "SELECT a.name, a.type, a.description, a.rule_name, a.created_at, a.updated_at, b.parent, c.description as parent_description, c.type as parent_type, c.rule_name as parent_rule_name, c.created_at as parent_created_at, c.updated_at as parent_updated_at FROM {$this->itemChildTable} as b INNER JOIN {$this->itemTable} as a on (a.name = b.child) INNER JOIN {$this->itemTable} as c on c.name = b.parent  WHERE c.type = :type";
        $rows = $this->db->select($sql, [':type' => $type]);

        $data = [];
        foreach ($rows as $row) {
            $row = (array)$row;
            if (empty($data[$row['parent']])) {
                $data[$row['parent']] = [
                    'parent'   => $this->populateItem([
                        'name'        => $row['parent'],
                        'description' => $row['parent_description'],
                        'type'        => $row['parent_type'],
                        'rule_name'   => $row['parent_rule_name'],
                        'created_at'  => $row['parent_created_at'],
                        'updated_at'  => $row['parent_updated_at'],
                    ]),
                    'children' => [],
                ];
            }
            $data[$row['parent']]['children'][$row['name']] = $this->populateItem($row);
        }
        return $data;
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

        $params = [':type' => Item::TYPE_PERMISSION];
        $sql = "SELECT * FROM {$this->itemTable} WHERE type = :type ";
        if (!empty($result)) {
            $p = [];
            foreach (array_keys($result) as $key => $value) {
                $n = ":q{$key}";
                $params[$n] = $value;
                $p[] = $n;
            }
            $in = implode(", ", $p);
            $sql .= " AND name in ( {$in} ) ";
        }

        $rows = $this->db->select($sql, $params);

        $permissions = [];
        foreach ($rows as $row) {
            $item = $this->populateItem($row);
            $permissions[$item->getName()] = $item;
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
        $sql = "SELECT b.* FROM {$this->assignmentTable} as a INNER JOIN {$this->itemTable} as b on a.item_name = b.name WHERE a.user_id = :user_id and b.type = :type";
        $rows = $this->db->select($sql, [':type' => Item::TYPE_PERMISSION, ':user_id' => $userId]);

        $permissions = [];
        foreach ($rows as $row) {
            $item = $this->populateItem($row);
            $permissions[$item->getName()] = $item;
        }

        return $permissions;
    }

    protected function getInheritedPermissionsByUser(string $userId): array
    {
        $rows = $this->db->select("SELECT item_name FROM {$this->assignmentTable} WHERE user_id = :user_id", [':user_id' => $userId]);
        $childrenList = $this->getChildrenList();
        $result = [];
        foreach ($rows as $roleName) {
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

        $row = $this->db->selectOne("SELECT data FROM {$this->ruleTable} WHERE name = :name LIMIT 1", [':name' => $name]);

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

        $rows = $this->db->select("select * from {$this->ruleTable}");

        $rules = [];
        foreach ($rows as $row) {
            $row = (array)$row;
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

        $this->insertData($this->itemChildTable, ['parent' => $parent->getName(), 'child' => $child->getName()]);

        $this->cleanCache();
    }

    /**
     * @inheritDoc
     */
    public function removeChild(Item $parent, Item $child): void
    {
        $this->deleteData($this->itemChildTable, ['parent' => $parent->getName(), 'child' => $child->getName()]);
        $this->cleanCache();
    }

    /**
     * @inheritDoc
     */
    public function removeChildren(Item $parent): void
    {
        $this->deleteData($this->itemChildTable, ['parent' => $parent->getName()]);
        $this->cleanCache();
    }

    /**
     * @inheritDoc
     */
    public function hasChild(Item $parent, Item $child): bool
    {
        $row = $this->db->selectOne("SELECT * FROM {$this->itemChildTable} WHERE parent = :parent AND child = :child LIMIT 1",
            [':parent' => $parent->getName(), 'child' => $child->getName()]);
        return !empty($row);
    }

    /**
     * @inheritDoc
     */
    public function getChildren(string $name): array
    {
        $sql = "SELECT a.name, a.type, a.description, a.rule_name, a.created_at, a.updated_at FROM {$this->itemTable} as a INNER JOIN {$this->itemChildTable} as b on a.name = b.child WHERE b.parent = :parent";
        $rows = $this->db->select($sql, [':parent' => $name]);

        $children = [];
        foreach ($rows as $row) {
            $item = $this->populateItem($row);
            $children[$item->getName()] = $item;
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
        $this->insertData($this->assignmentTable, $assignment->getAttributes());
        unset($this->_checkAccessAssignments[$userId]);
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
        unset($this->_checkAccessAssignments[$userId]);
        $this->deleteData($this->assignmentTable, ['user_id' => $userId, 'item_name' => $item->getName()]);
    }

    /**
     * @inheritDoc
     */
    public function revokeAll(string $userId): void
    {
        if ($this->isEmptyUserId($userId)) {
            return;
        }
        unset($this->_checkAccessAssignments[$userId]);
        $this->deleteData($this->assignmentTable, ['user_id' => $userId]);
    }

    /**
     * @inheritDoc
     */
    public function getAssignment(string $itemName, string $userId): ?Assignment
    {
        if ($this->isEmptyUserId($userId)) {
            return null;
        }

        $row = $this->db->selectOne("SELECT * FROM {$this->assignmentTable} WHERE user_id = :user_id AND item_name = :item_name LIMIT 1",
            [':user_id' => $userId, ':item_name' => $itemName]);

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

        $rows = $this->db->select("SELECT * FROM {$this->assignmentTable} WHERE user_id = :user_id", [':user_id' => $userId]);

        $assignments = [];
        foreach ($rows as $row) {
            $row = (array)$row;
            $item = new Assignment($row['user_id'], $row['item_name'], $row['created_at']);
            $assignments[$item->getItemName()] = $item;
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
        $rows = $this->db->select("SELECT user_id FROM {$this->assignmentTable} WHERE item_name = :item_name", [':item_name' => $roleName]);

        return !empty($rows) ? array_column($rows, 'user_id') : [];
    }

    /**
     * @inheritDoc
     */
    public function removeAll(): void
    {
        $this->removeAllAssignments();
        $this->deleteData($this->itemChildTable);
        $this->deleteData($this->itemTable);
        $this->removeAllRules();
        $this->cleanCache();
    }

    /**
     * @inheritDoc
     */
    public function removeAllPermissions(): void
    {
        $this->deleteData($this->itemTable, ['type' => Item::TYPE_PERMISSION]);
        $this->cleanCache();
    }

    /**
     * @inheritDoc
     */
    public function removeAllRoles(): void
    {
        $this->deleteData($this->itemTable, ['type' => Item::TYPE_ROLE]);
        $this->cleanCache();
    }

    /**
     * @inheritDoc
     */
    public function removeAllRules(): void
    {
        $this->deleteData($this->ruleTable);
    }

    /**
     * @inheritDoc
     */
    public function removeAllAssignments(): void
    {
        $this->_checkAccessAssignments = [];
        $this->deleteData($this->assignmentTable);
    }

    protected function addMenu(Menu $menu): void
    {
        $time = time();
        $menu = $menu->withCreatedAt($time)->withUpdatedAt($time);
        $this->insertData($this->menuTable, $menu->getAttributes());
        $this->cleanCache();
    }

    protected function removeMenu(Menu $menu): void
    {
        $this->deleteData($this->menuTable, ['name' => $menu->getName()]);
        $this->cleanCache();
    }

    protected function updateMenu(string $name, Menu $menu): void
    {
        $menu = $menu->withUpdatedAt(time());
        $this->updateData($this->menuTable, $menu->getAttributes(), ['name' => $name,]);
        $this->cleanCache();
    }

    public function populateMenu($row): Menu
    {
        $row = (array)$row;
        return (new Menu($row['name']))->withPid($row['pid'])
            ->withIcon($row['icon'])
            ->withPath($row['path'])
            ->withSort($row['sort'])
            ->withTemplate($row['template'])
            ->withRole($row['role'])
            ->withCreatedAt($row['created_at'])
            ->withUpdatedAt($row['updated_at']);
    }

    public function getMenu(string $name): ?Menu
    {
        if ($this->isEmptyName($name)) {
            return null;
        }

        $row = $this->db->selectOne("SELECT * FROM {$this->menuTable} WHERE name = :name LIMIT 1", [':name' => $name]);

        if ($row === false) {
            return null;
        }

        return $this->populateMenu($row);
    }

    /**
     * @param string $role
     *
     * @return array
     */
    public function getMenus(string $role = ''): array
    {
        $where = '';
        $params = [];
        if (!$this->isEmptyName($role)) {
            $where = 'WHERE role = :role';
            $params = [':role' => $role];
        }

        $rows = $this->db->select("SELECT * FROM {$this->menuTable} {$where} ORDER BY sort", $params);
        $items = [];
        foreach ($rows as $row) {
            $item = $this->populateMenu($row);
            $items[$item->getName()] = $item;
        }
        return $items;
    }
}
