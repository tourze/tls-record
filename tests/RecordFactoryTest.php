<?php

namespace Tourze\TLSRecord\Tests;

use PHPUnit\Framework\TestCase;
use Tourze\TLSCommon\Version;
use Tourze\TLSRecord\Exception\RecordException;
use Tourze\TLSRecord\RecordFactory;
use Tourze\TLSRecord\RecordLayer;
use Tourze\TLSRecord\RecordProtocol;
use Tourze\TLSRecord\Tests\Mock\MockTransport;

/**
 * RecordFactory类单元测试
 */
class RecordFactoryTest extends TestCase
{
    /**
     * 测试使用有效的TLS版本创建记录层
     */
    public function testCreateWithValidVersion(): void
    {
        // 使用TLS 1.0
        $transport = new MockTransport();
        $recordLayer = RecordFactory::create($transport, Version::TLS_1_0->value);
        $this->assertInstanceOf(RecordProtocol::class, $recordLayer);
        $this->assertInstanceOf(RecordLayer::class, $recordLayer);
        
        // 使用TLS 1.1
        $recordLayer = RecordFactory::create($transport, Version::TLS_1_1->value);
        $this->assertInstanceOf(RecordProtocol::class, $recordLayer);
        $this->assertInstanceOf(RecordLayer::class, $recordLayer);
        
        // 使用TLS 1.2
        $recordLayer = RecordFactory::create($transport, Version::TLS_1_2->value);
        $this->assertInstanceOf(RecordProtocol::class, $recordLayer);
        $this->assertInstanceOf(RecordLayer::class, $recordLayer);
        
        // 使用TLS 1.3
        $recordLayer = RecordFactory::create($transport, Version::TLS_1_3->value);
        $this->assertInstanceOf(RecordProtocol::class, $recordLayer);
        $this->assertInstanceOf(RecordLayer::class, $recordLayer);
    }
    
    /**
     * 测试使用无效的TLS版本创建记录层时抛出异常
     */
    public function testCreateWithInvalidVersionThrowsException(): void
    {
        $transport = new MockTransport();
        
        // 使用无效的TLS版本
        $this->expectException(RecordException::class);
        $this->expectExceptionMessage('不支持的TLS版本');
        
        RecordFactory::create($transport, 0x0100); // 无效版本
    }
    
    /**
     * 测试不同传输层的适配
     */
    public function testDifferentTransports(): void
    {
        // 创建不同配置的传输层
        $transport1 = new MockTransport();
        $transport1->setHasDataAvailable(true);
        
        $transport2 = new MockTransport();
        $transport2->setHasDataAvailable(false);
        
        // 验证两个传输层都能创建记录层
        $recordLayer1 = RecordFactory::create($transport1, Version::TLS_1_2->value);
        $this->assertInstanceOf(RecordProtocol::class, $recordLayer1);
        
        $recordLayer2 = RecordFactory::create($transport2, Version::TLS_1_2->value);
        $this->assertInstanceOf(RecordProtocol::class, $recordLayer2);
    }
    
    /**
     * 测试边界和极端版本值
     */
    public function testBoundaryVersions(): void
    {
        $transport = new MockTransport();
        
        // 测试SSL 3.0 (不支持)
        $this->expectException(RecordException::class);
        RecordFactory::create($transport, 0x0300); // SSL 3.0
    }
} 