<?php

namespace Doctrine\Tests;

use Doctrine\Common\Annotations\AnnotationRegistry;

$classLoader = require 'vendor/autoload.php';

/* @var $classLoader \Composer\Autoload\ClassLoader */
$classLoader->add('DoctrineEncrypt\\Tests\\', "tests");

AnnotationRegistry::registerLoader(array($classLoader, 'loadClass'));
unset($classLoader);