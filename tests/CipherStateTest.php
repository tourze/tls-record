<?php

namespace Tourze\TLSRecord\Tests;

use PHPUnit\Framework\TestCase;
use Tourze\TLSCommon\Version;
use Tourze\TLSRecord\CipherState;

/**
 * CipherState类单元测试
 */
class CipherStateTest extends TestCase
{
    /**
     * 测试基本属性设置和获取
     */
    public function testBasicProperties(): void
    {
        // 创建测试数据
        $cipherSuite = 'TLS_AES_128_GCM_SHA256';
        $key = str_repeat('k', 16);
        $iv = str_repeat('i', 12);
        $macKey = str_repeat('m', 16);
        $version = Version::TLS_1_2->value;
        
        // 创建加密状态
        $state = new CipherState($cipherSuite, $key, $iv, $macKey, $version);
        
        // 验证属性获取方法
        $this->assertEquals($cipherSuite, $state->getCipherSuite());
        $this->assertEquals($key, $state->getKey());
        $this->assertEquals($iv, $state->getIV());
        $this->assertEquals($macKey, $state->getMacKey());
        $this->assertEquals($version, $state->getTLSVersion());
    }
    
    /**
     * 测试序列号管理
     */
    public function testSequenceNumberManagement(): void
    {
        // 创建加密状态
        $state = new CipherState(
            'TLS_AES_128_GCM_SHA256',
            str_repeat('k', 16),
            str_repeat('i', 12),
            str_repeat('m', 16),
            Version::TLS_1_2->value
        );
        
        // 初始序列号应该是0
        $this->assertEquals(0, $state->getSequenceNumber());
        
        // 获取并递增序列号
        $this->assertEquals(0, $state->getAndIncrementSequenceNumber());
        
        // 序列号应该已递增为1
        $this->assertEquals(1, $state->getSequenceNumber());
        
        // 再次获取并递增
        $this->assertEquals(1, $state->getAndIncrementSequenceNumber());
        $this->assertEquals(2, $state->getSequenceNumber());
    }
    
    /**
     * 测试大量序列号递增
     */
    public function testLargeSequenceNumberIncrement(): void
    {
        // 创建加密状态
        $state = new CipherState(
            'TLS_AES_128_GCM_SHA256',
            str_repeat('k', 16),
            str_repeat('i', 12),
            str_repeat('m', 16),
            Version::TLS_1_2->value
        );
        
        // 模拟大量递增操作
        $expectedSeq = 0;
        for ($i = 0; $i < 1000; $i++) {
            $this->assertEquals($expectedSeq, $state->getAndIncrementSequenceNumber());
            $expectedSeq++;
        }
        
        // 最终序列号应该是1000
        $this->assertEquals(1000, $state->getSequenceNumber());
    }
    
    /**
     * 测试不同TLS版本设置
     */
    public function testDifferentTLSVersions(): void
    {
        // 测试TLS 1.0版本
        $state1 = new CipherState(
            'TLS_RSA_WITH_AES_128_CBC_SHA',
            str_repeat('k', 16),
            str_repeat('i', 16),
            str_repeat('m', 20),
            Version::TLS_1_0->value
        );
        
        $this->assertEquals(Version::TLS_1_0->value, $state1->getTLSVersion());
        
        // 测试TLS 1.1版本
        $state2 = new CipherState(
            'TLS_RSA_WITH_AES_256_CBC_SHA',
            str_repeat('k', 32),
            str_repeat('i', 16),
            str_repeat('m', 20),
            Version::TLS_1_1->value
        );
        
        $this->assertEquals(Version::TLS_1_1->value, $state2->getTLSVersion());
        
        // 测试TLS 1.3版本
        $state3 = new CipherState(
            'TLS_AES_256_GCM_SHA384',
            str_repeat('k', 32),
            str_repeat('i', 12),
            '',  // TLS 1.3不使用独立的MAC密钥
            Version::TLS_1_3->value
        );
        
        $this->assertEquals(Version::TLS_1_3->value, $state3->getTLSVersion());
    }
} 