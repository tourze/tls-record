<?php

namespace Tourze\TLSRecord;

/**
 * TLS加密状态类，用于管理记录层的加密和MAC状态
 */
class CipherState
{
    /**
     * 当前序列号
     */
    private int $sequenceNumber = 0;
    
    /**
     * 构造函数
     *
     * @param string $cipherSuite 加密套件名称
     * @param string $key 加密密钥
     * @param string $iv 初始化向量
     * @param string $macKey MAC密钥
     * @param int $tlsVersion TLS版本
     */
    public function __construct(
        private readonly string $cipherSuite,
        private readonly string $key,
        private readonly string $iv,
        private readonly string $macKey,
        private readonly int $tlsVersion
    ) {
    }
    
    /**
     * 获取当前序列号并递增
     */
    public function getAndIncrementSequenceNumber(): int
    {
        $currentSeq = $this->sequenceNumber;
        $this->sequenceNumber++;
        
        // 确保序列号不超过64位最大值，超过则循环回0
        if ($this->sequenceNumber < 0) {
            $this->sequenceNumber = 0;
        }
        
        return $currentSeq;
    }
    
    /**
     * 获取当前序列号
     */
    public function getSequenceNumber(): int
    {
        return $this->sequenceNumber;
    }
    
    /**
     * 获取加密套件名称
     */
    public function getCipherSuite(): string
    {
        return $this->cipherSuite;
    }
    
    /**
     * 获取加密密钥
     */
    public function getKey(): string
    {
        return $this->key;
    }
    
    /**
     * 获取初始化向量
     */
    public function getIV(): string
    {
        return $this->iv;
    }
    
    /**
     * 获取MAC密钥
     */
    public function getMacKey(): string
    {
        return $this->macKey;
    }
    
    /**
     * 获取TLS版本
     */
    public function getTLSVersion(): int
    {
        return $this->tlsVersion;
    }
}
