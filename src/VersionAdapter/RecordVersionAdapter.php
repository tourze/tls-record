<?php

namespace Tourze\TLSRecord\VersionAdapter;

use Tourze\TLSRecord\CipherState;
use Tourze\TLSRecord\RecordData;

/**
 * TLS记录版本适配器接口，用于处理不同TLS版本的记录格式差异
 */
interface RecordVersionAdapter
{
    /**
     * 将记录数据编码为二进制格式
     *
     * @param RecordData $record 记录数据
     * @return string 编码后的二进制数据
     */
    public function encodeRecord(RecordData $record): string;
    
    /**
     * 从二进制数据解码记录
     *
     * @param string $data 二进制数据
     * @return RecordData 解码后的记录数据
     */
    public function decodeRecord(string $data): RecordData;
    
    /**
     * 对明文数据应用加密
     *
     * @param string $plaintext 明文数据
     * @param CipherState $state 加密状态
     * @param int $contentType 原始内容类型
     * @return string 加密后的数据
     */
    public function applyEncryption(string $plaintext, CipherState $state, int $contentType): string;
    
    /**
     * 对密文数据应用解密
     *
     * @param string $ciphertext 密文数据
     * @param CipherState $state 加密状态
     * @return array 包含解密后的数据和原始内容类型的数组 [string $plaintext, int $contentType]
     */
    public function applyDecryption(string $ciphertext, CipherState $state): array;
}
