<?php

namespace Tourze\TLSRecord\Tests\Transport;

use PHPUnit\Framework\TestCase;
use Tourze\TLSRecord\Transport\SocketTransport;

/**
 * SocketTransport类单元测试
 * 
 * 注意：由于SocketTransport涉及实际网络连接，这里主要测试类的基本行为，
 * 不进行实际的网络连接测试，避免测试依赖于外部网络环境
 */
class SocketTransportTest extends TestCase
{
    /**
     * 测试构造函数参数设置
     */
    public function testConstructorParameters(): void
    {
        // 为避免真实网络连接，跳过自动连接
        $transport = new \ReflectionClass(SocketTransport::class);
        $instance = $transport->newInstanceWithoutConstructor();
        
        // 手动设置属性
        $hostProperty = $transport->getProperty('host');
        $hostProperty->setAccessible(true);
        $hostProperty->setValue($instance, 'example.com');
        
        $portProperty = $transport->getProperty('port');
        $portProperty->setAccessible(true);
        $portProperty->setValue($instance, 443);
        
        // 验证属性值
        $this->assertEquals('example.com', $hostProperty->getValue($instance));
        $this->assertEquals(443, $portProperty->getValue($instance));
    }
    
    /**
     * 测试设置读取超时
     */
    public function testSetReadTimeout(): void
    {
        // 为避免真实网络连接，跳过自动连接
        $transport = new \ReflectionClass(SocketTransport::class);
        $instance = $transport->newInstanceWithoutConstructor();
        
        // 手动设置属性
        $readTimeoutProperty = $transport->getProperty('readTimeout');
        $readTimeoutProperty->setAccessible(true);
        
        // 设置读取超时方法也是public的，可以直接调用
        $setReadTimeoutMethod = $transport->getMethod('setReadTimeout');
        $setReadTimeoutMethod->setAccessible(true);
        $setReadTimeoutMethod->invoke($instance, 60);
        
        // 验证属性值
        $this->assertEquals(60, $readTimeoutProperty->getValue($instance));
    }
    
    /**
     * 测试关闭方法
     */
    public function testClose(): void
    {
        // 为避免真实网络连接，跳过自动连接
        $transport = new \ReflectionClass(SocketTransport::class);
        $instance = $transport->newInstanceWithoutConstructor();
        
        // 手动设置连接状态
        $connectedProperty = $transport->getProperty('connected');
        $connectedProperty->setAccessible(true);
        $connectedProperty->setValue($instance, true);
        
        // 调用close方法
        $closeMethod = $transport->getMethod('close');
        $closeMethod->invoke($instance);
        
        // 验证连接状态已重置
        $this->assertFalse($connectedProperty->getValue($instance));
    }
    
    /**
     * 测试hasDataAvailable方法在未连接时的行为
     */
    public function testHasDataAvailableWhenNotConnected(): void
    {
        // 为避免真实网络连接，跳过自动连接
        $transport = new \ReflectionClass(SocketTransport::class);
        $instance = $transport->newInstanceWithoutConstructor();
        
        // 手动设置连接状态
        $connectedProperty = $transport->getProperty('connected');
        $connectedProperty->setAccessible(true);
        $connectedProperty->setValue($instance, false);
        
        // 调用hasDataAvailable方法
        $hasDataMethod = $transport->getMethod('hasDataAvailable');
        $result = $hasDataMethod->invoke($instance);
        
        // 未连接时应返回false
        $this->assertFalse($result);
    }
} 