<?php

namespace Tourze\TLSRecord;

/**
 * TLS记录层协议接口，定义了记录层的核心功能
 */
interface RecordProtocol
{
    /**
     * 发送TLS记录
     *
     * @param int $contentType 内容类型（参见ContentType类）
     * @param string $data 要发送的数据
     * @return void
     * @throws \Exception 发送失败时抛出异常
     */
    public function sendRecord(int $contentType, string $data): void;
    
    /**
     * 接收TLS记录
     *
     * @return RecordData 接收到的记录数据
     * @throws \Exception 接收失败时抛出异常
     */
    public function receiveRecord(): RecordData;
    
    /**
     * 切换写入方向的加密状态
     *
     * @param CipherState $state 新的加密状态
     * @return void
     */
    public function changeWriteCipherSpec(CipherState $state): void;
    
    /**
     * 切换读取方向的加密状态
     *
     * @param CipherState $state 新的加密状态
     * @return void
     */
    public function changeReadCipherSpec(CipherState $state): void;
    
    /**
     * 设置最大片段长度
     *
     * @param int $length 最大片段长度
     * @return void
     */
    public function setMaxFragmentLength(int $length): void;
    
    /**
     * 设置是否启用防重放保护
     *
     * @param bool $enabled 是否启用
     * @return void
     */
    public function setReplayProtection(bool $enabled): void;
    
    /**
     * 获取当前防重放保护是否启用
     *
     * @return bool 是否启用
     */
    public function isReplayProtectionEnabled(): bool;
}
