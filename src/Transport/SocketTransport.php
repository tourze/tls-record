<?php

namespace Tourze\TLSRecord\Transport;

use Tourze\TLSRecord\Exception\RecordException;

/**
 * 基于TCP套接字的传输层实现
 */
class SocketTransport implements Transport
{
    /**
     * 套接字资源
     *
     * @var \Socket|null
     */
    private ?\Socket $socket = null;
    
    /**
     * 是否已连接
     */
    private bool $connected = false;
    
    /**
     * 读取超时（秒）
     */
    private int $readTimeout = 30;
    
    /**
     * 构造函数
     *
     * @param string $host 目标主机名或IP
     * @param int $port 目标端口
     * @param int $timeout 连接超时（秒）
     * @param bool $autoConnect 是否自动连接
     * @throws RecordException 如果自动连接失败
     */
    public function __construct(
        private readonly string $host,
        private readonly int $port,
        private readonly int $timeout = 30,
        bool $autoConnect = true
    ) {
        if ($autoConnect) {
            $this->connect();
        }
    }
    
    /**
     * 连接到远程服务器
     *
     * @throws RecordException 如果连接失败
     */
    public function connect(): void
    {
        if ($this->connected) {
            return;
        }
        
        // 创建TCP套接字
        $socket = @socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
        if ($socket === false) {
            throw new RecordException('创建套接字失败: ' . socket_strerror(socket_last_error()));
        }
        $this->socket = $socket;
        
        // 设置超时选项
        socket_set_option($this->socket, SOL_SOCKET, SO_RCVTIMEO, ['sec' => $this->timeout, 'usec' => 0]);
        socket_set_option($this->socket, SOL_SOCKET, SO_SNDTIMEO, ['sec' => $this->timeout, 'usec' => 0]);
        
        // 连接到远程服务器
        $result = @socket_connect($this->socket, $this->host, $this->port);
        if ($result === false) {
            $error = socket_strerror(socket_last_error($this->socket));
            socket_close($this->socket);
            $this->socket = null;
            throw new RecordException('连接到 ' . $this->host . ':' . $this->port . ' 失败: ' . $error);
        }
        
        // 设置为非阻塞模式
        socket_set_nonblock($this->socket);
        
        $this->connected = true;
    }
    
    /**
     * 向套接字发送数据
     */
    public function send(string $data): int
    {
        if (!$this->connected || $this->socket === null) {
            throw new RecordException('未连接到服务器');
        }
        
        $totalSent = 0;
        $dataLength = strlen($data);
        
        while ($totalSent < $dataLength) {
            $sent = @socket_write($this->socket, substr($data, $totalSent), $dataLength - $totalSent);
            
            if ($sent === false) {
                $error = socket_strerror(socket_last_error($this->socket));
                throw new RecordException('发送数据失败: ' . $error);
            }
            
            if ($sent === 0) {
                throw new RecordException('连接已关闭');
            }
            
            $totalSent += $sent;
        }
        
        return $totalSent;
    }
    
    /**
     * 从套接字接收数据
     */
    public function receive(int $length): string
    {
        if (!$this->connected || $this->socket === null) {
            throw new RecordException('未连接到服务器');
        }
        
        $buffer = '';
        $startTime = time();
        
        while (strlen($buffer) < $length) {
            // 检查是否超时
            if (time() - $startTime > $this->readTimeout) {
                throw new RecordException('接收数据超时');
            }
            
            // 检查是否有可读数据
            $read = [$this->socket];
            $write = null;
            $except = null;
            $ready = socket_select($read, $write, $except, 1, 0);
            
            if ($ready === false) {
                $error = socket_strerror(socket_last_error($this->socket));
                throw new RecordException('选择套接字失败: ' . $error);
            }
            
            if ($ready === 0) {
                // 暂时没有可读数据，继续等待
                continue;
            }
            
            // 接收可用数据
            $data = socket_read($this->socket, $length - strlen($buffer), PHP_BINARY_READ);
            
            if ($data === false) {
                $error = socket_strerror(socket_last_error($this->socket));
                throw new RecordException('接收数据失败: ' . $error);
            }
            
            if ($data === '') {
                // 远程端已关闭连接
                $this->connected = false;
                if (strlen($buffer) === 0) {
                    throw new RecordException('连接已关闭');
                }
                break;
            }
            
            $buffer .= $data;
            
            // 如果接收到一些数据但未达到请求的长度，则返回已接收的数据
            // 这对于TLS记录层来说是可以接受的，因为它可以处理部分记录
            if (strlen($buffer) > 0 && strlen($buffer) < $length) {
                break;
            }
        }
        
        return $buffer;
    }
    
    /**
     * 检查是否有可读取的数据
     */
    public function hasDataAvailable(int $timeout = 0): bool
    {
        if (!$this->connected || $this->socket === null) {
            return false;
        }
        
        $read = [$this->socket];
        $write = null;
        $except = null;
        $sec = (int) ($timeout / 1000);
        $usec = ($timeout % 1000) * 1000;
        
        $ready = socket_select($read, $write, $except, $sec, $usec);
        
        return $ready > 0;
    }
    
    /**
     * 关闭套接字连接
     */
    public function close(): void
    {
        if ($this->socket !== null) {
            socket_close($this->socket);
            $this->socket = null;
        }
        
        $this->connected = false;
    }
    
    /**
     * 析构函数，自动关闭连接
     */
    public function __destruct()
    {
        $this->close();
    }
    
    /**
     * 设置读取超时
     *
     * @param int $seconds 超时秒数
     */
    public function setReadTimeout(int $seconds): void
    {
        $this->readTimeout = $seconds;
        
        if ($this->socket !== null) {
            socket_set_option($this->socket, SOL_SOCKET, SO_RCVTIMEO, ['sec' => $seconds, 'usec' => 0]);
        }
    }
} 