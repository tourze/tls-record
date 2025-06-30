<?php

namespace Tourze\TLSRecord\Tests\Mock;

use PHPUnit\Framework\TestCase;

class MockTransportTest extends TestCase
{
    private MockTransport $transport;
    
    protected function setUp(): void
    {
        parent::setUp();
        $this->transport = new MockTransport();
    }
    
    public function testConstructorWithInitialData(): void
    {
        $initialData = ['data1', 'data2', 'data3'];
        $transport = new MockTransport($initialData);
        
        // 验证初始数据可以被接收
        $this->assertEquals('data1', $transport->receive(10));
        $this->assertEquals('data2', $transport->receive(10));
        $this->assertEquals('data3', $transport->receive(10));
        $this->assertEquals('', $transport->receive(10)); // 队列为空
    }
    
    public function testSend(): void
    {
        // 发送数据
        $bytes1 = $this->transport->send('Hello');
        $this->assertEquals(5, $bytes1);
        
        $bytes2 = $this->transport->send('World');
        $this->assertEquals(5, $bytes2);
        
        // 验证已发送的数据
        $sentData = $this->transport->getSentData();
        $this->assertCount(2, $sentData);
        $this->assertEquals('Hello', $sentData[0]);
        $this->assertEquals('World', $sentData[1]);
    }
    
    public function testReceive(): void
    {
        // 添加数据到接收队列
        $this->transport->queueReceiveData('First message');
        $this->transport->queueReceiveData('Second message');
        
        // 接收数据
        $data1 = $this->transport->receive(100);
        $this->assertEquals('First message', $data1);
        
        $data2 = $this->transport->receive(100);
        $this->assertEquals('Second message', $data2);
        
        // 队列为空时返回空字符串
        $data3 = $this->transport->receive(100);
        $this->assertEquals('', $data3);
    }
    
    public function testReceiveWithLengthLimit(): void
    {
        $this->transport->queueReceiveData('Hello World');
        
        // 只接收5个字节
        $data = $this->transport->receive(5);
        $this->assertEquals('Hello', $data);
        
        // 注意：MockTransport的简单实现会丢弃剩余的数据
        // 下次接收会返回空字符串（因为整个消息已经从队列移除）
        $data2 = $this->transport->receive(10);
        $this->assertEquals('', $data2);
    }
    
    public function testHasDataAvailable(): void
    {
        // 初始状态，没有数据但标志为true
        $this->assertFalse($this->transport->hasDataAvailable());
        
        // 添加数据
        $this->transport->queueReceiveData('Some data');
        $this->assertTrue($this->transport->hasDataAvailable());
        
        // 接收数据后
        $this->transport->receive(100);
        $this->assertFalse($this->transport->hasDataAvailable());
        
        // 设置标志为false
        $this->transport->queueReceiveData('More data');
        $this->transport->setHasDataAvailable(false);
        $this->assertFalse($this->transport->hasDataAvailable());
        
        // 恢复标志
        $this->transport->setHasDataAvailable(true);
        $this->assertTrue($this->transport->hasDataAvailable());
    }
    
    public function testClose(): void
    {
        // 添加一些数据
        $this->transport->queueReceiveData('Data to clear');
        $this->transport->send('Sent data');
        
        // 验证数据存在
        $this->assertTrue($this->transport->hasDataAvailable());
        $this->assertNotEmpty($this->transport->getSentData());
        
        // 关闭传输层
        $this->transport->close();
        
        // 验证数据被清空
        $this->assertFalse($this->transport->hasDataAvailable());
        $this->assertEmpty($this->transport->getSentData());
        $this->assertEquals('', $this->transport->receive(100));
    }
    
    public function testQueueReceiveData(): void
    {
        // 逐个添加数据
        $this->transport->queueReceiveData('First');
        $this->transport->queueReceiveData('Second');
        $this->transport->queueReceiveData('Third');
        
        // 按顺序接收
        $this->assertEquals('First', $this->transport->receive(100));
        $this->assertEquals('Second', $this->transport->receive(100));
        $this->assertEquals('Third', $this->transport->receive(100));
    }
    
    public function testMultipleSendReceiveCycles(): void
    {
        // 第一轮
        $this->transport->send('Request 1');
        $this->transport->queueReceiveData('Response 1');
        $this->assertEquals('Response 1', $this->transport->receive(100));
        
        // 第二轮
        $this->transport->send('Request 2');
        $this->transport->queueReceiveData('Response 2');
        $this->assertEquals('Response 2', $this->transport->receive(100));
        
        // 验证所有发送的数据
        $sentData = $this->transport->getSentData();
        $this->assertCount(2, $sentData);
        $this->assertEquals('Request 1', $sentData[0]);
        $this->assertEquals('Request 2', $sentData[1]);
    }
}