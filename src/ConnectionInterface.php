<?php

namespace Lengbin\YiiSoft\Rbac;

interface ConnectionInterface
{
    /**
     * Run a select statement and return a single result.
     *
     * @param string $query
     * @param array  $bindings
     */
    public function selectOne(string $query, array $bindings = []);

    /**
     * Run a select statement against the database.
     *
     * @param string $query
     * @param array  $bindings
     *
     * @return array
     */
    public function select(string $query, array $bindings = []);

    /**
     * Run an insert statement against the database.
     *
     * @param string $query
     * @param array  $bindings
     *
     * @return bool
     */
    public function insert(string $query, array $bindings = []): bool;

    /**
     * Run an update statement against the database.
     *
     * @param string $query
     * @param array  $bindings
     *
     * @return int
     */
    public function update(string $query, array $bindings = []): int;

    /**
     * Run a delete statement against the database.
     *
     * @param string $query
     * @param array  $bindings
     *
     * @return int
     */
    public function delete(string $query, array $bindings = []): int;
}
