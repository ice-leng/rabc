<p align="center">
    <a href="https://github.com/yiisoft" target="_blank">
        <img src="https://avatars0.githubusercontent.com/u/993323" height="100px">
    </a>
    <h1 align="center">Yii Rabc</h1>
    <br>
</p>

这是基于[yii-rbac](https://github.com/yiisoft/rbac)修改抽离扩展版本
适合于（除yii）php框架

安装
------------

The preferred way to install this extension is through [composer](http://getcomposer.org/download/).

Either run

```
composer require lengbin/yii-rbac
```

or add

```
"lengbin/yii-rbac": "*"
```
to the require section of your `composer.json` file.

Usage
-----

## 用法和yii 是一致的


```php
        
        // 缓存cache 
        $manager = new PhpManager(new ClassNameRuleFactory(), $this->container->get(CacheInterface::class));
        // 文件
//        $manager = new PhpManagerFile(new ClassNameRuleFactory());
       // 数据库
//        $manager = new DbManager(new ClassNameRuleFactory(), new Connection($this->container), null, $this->container->get(LoggerInterface::class)->get());


        $manager->add(new Permission('createPost'));
        $manager->add(new Permission('readPost'));
        $manager->add(new Permission('deletePost'));

        $manager->add(new Role('author'));
        $manager->add(new Role('reader'));


        $manager->addChild($manager->getRole('reader'), $manager->getPermission('readPost'));

        $manager->addChild($manager->getRole('author'), $manager->getPermission('createPost'));

        $manager->addChild($manager->getRole('author'), $manager->getRole('reader'));

        $manager->assign($manager->getRole('author'), "100");

        if ($manager->userHasPermission("100", 'createPost')) {
            echo 'author has permission createPost';
        }

        $manager->add(new ActionRule());
        $manager->add((new Permission('viewList'))->withRuleName('action_rule'));

        $manager->addChild($manager->getRole('author'), $manager->getPermission('viewList'));

        var_dump($manager->userHasPermission('100', 'viewList', ['action' => 'home']), $manager->userHasPermission('100', 'viewList', ['action' => 'home2']));

        var_dump($manager->getPermission('createPost')->getAttributes(), $manager->getRoles(), $manager->getRules());

        var_dump($manager->getPermissions());
        $manager->remove(new Permission('viewList'));
        var_dump($manager->getPermissions());

        $manager->removeAll();

```

```php

// 规则
class ActionRule extends Rule
{
    public function __construct()
    {
        parent::__construct('action_rule');
    }

    public function execute(string $userId, Item $item, array $parameters = []): bool
    {
        return isset($parameters['action']) && $parameters['action'] === 'home';
    }
}

```

其他
----
有问题请及时联系我，反正也会在使用中修复 - - ！


