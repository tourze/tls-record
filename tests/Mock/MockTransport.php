<?php

namespace Tourze\TLSRecord\Tests\Mock;

use Tourze\TLSRecord\Transport\Transport;

/**
 * 模拟传输层实现，用于单元测试
 */
class MockTransport implements Transport
{
    /**
     * 要返回的接收数据队列
     */
    private array $receiveQueue = [];
    
    /**
     * 已发送的数据
     */
    private array $sentData = [];
    
    /**
     * 是否有可用数据的标志
     */
    private bool $hasDataAvailable = true;
    
    /**
     * 构造函数
     */
    public function __construct(array $receiveData = [])
    {
        $this->receiveQueue = $receiveData;
    }
    
    /**
     * 添加模拟的接收数据到队列
     */
    public function queueReceiveData(string $data): void
    {
        $this->receiveQueue[] = $data;
    }
    
    /**
     * 获取已发送的所有数据
     */
    public function getSentData(): array
    {
        return $this->sentData;
    }
    
    /**
     * 设置是否有可用数据的标志
     */
    public function setHasDataAvailable(bool $value): void
    {
        $this->hasDataAvailable = $value;
    }
    
    /**
     * {@inheritdoc}
     */
    public function send(string $data): int
    {
        $this->sentData[] = $data;
        return strlen($data);
    }
    
    /**
     * {@inheritdoc}
     */
    public function receive(int $length): string
    {
        if (empty($this->receiveQueue)) {
            return '';
        }
        
        $data = array_shift($this->receiveQueue);
        return $length >= strlen($data) ? $data : substr($data, 0, $length);
    }
    
    /**
     * {@inheritdoc}
     */
    public function hasDataAvailable(int $timeout = 0): bool
    {
        return $this->hasDataAvailable && !empty($this->receiveQueue);
    }
    
    /**
     * {@inheritdoc}
     */
    public function close(): void
    {
        // 清空队列和已发送数据
        $this->receiveQueue = [];
        $this->sentData = [];
    }
} 