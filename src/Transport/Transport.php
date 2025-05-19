<?php

namespace Tourze\TLSRecord\Transport;

/**
 * 传输层接口，用于TLS记录层和底层网络传输的交互
 */
interface Transport
{
    /**
     * 向底层传输发送数据
     *
     * @param string $data 要发送的数据
     * @return int 发送的字节数
     */
    public function send(string $data): int;
    
    /**
     * 从底层传输接收数据
     *
     * @param int $length 要接收的最大字节数
     * @return string 接收到的数据
     */
    public function receive(int $length): string;
    
    /**
     * 检查是否有可读取的数据
     *
     * @param int $timeout 等待超时时间（毫秒）
     * @return bool 是否有数据可读
     */
    public function hasDataAvailable(int $timeout = 0): bool;
    
    /**
     * 关闭传输连接
     *
     * @return void
     */
    public function close(): void;
}
