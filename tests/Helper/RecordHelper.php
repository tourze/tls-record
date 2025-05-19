<?php

namespace Tourze\TLSRecord\Tests\Helper;

use Tourze\TLSCommon\Protocol\ContentType;

/**
 * TLS记录构建辅助类，用于单元测试
 */
class RecordHelper
{
    /**
     * 构建TLS记录二进制数据
     *
     * @param int $contentType 内容类型
     * @param int $version TLS版本号
     * @param string $data 记录数据
     * @return string TLS记录二进制数据
     */
    public static function buildRecord(int $contentType, int $version, string $data): string
    {
        // 构建TLS记录头部 (5字节)
        // - 1字节: 内容类型 (content_type)
        // - 2字节: 协议版本 (protocol_version)
        // - 2字节: 长度 (length)
        $header = pack(
            'CCC', 
            $contentType,                  // 内容类型
            ($version >> 8) & 0xFF,        // 主版本号
            $version & 0xFF                 // 次版本号
        );
        
        // 添加长度 (2字节, 网络字节序)
        $header .= pack('n', strlen($data));
        
        // 组合头部和数据
        return $header . $data;
    }
    
    /**
     * 构建多个连续的TLS记录
     *
     * @param array $records 记录配置数组，每个元素为 [contentType, version, data]
     * @return string 连续的TLS记录二进制数据
     */
    public static function buildMultipleRecords(array $records): string
    {
        $result = '';
        foreach ($records as [$contentType, $version, $data]) {
            $result .= self::buildRecord($contentType, $version, $data);
        }
        return $result;
    }
    
    /**
     * 创建握手记录
     *
     * @param int $version TLS版本号
     * @param string $data 握手数据
     * @return string TLS握手记录二进制数据
     */
    public static function buildHandshakeRecord(int $version, string $data): string
    {
        return self::buildRecord(ContentType::HANDSHAKE->value, $version, $data);
    }
    
    /**
     * 创建应用数据记录
     *
     * @param int $version TLS版本号
     * @param string $data 应用数据
     * @return string TLS应用数据记录二进制数据
     */
    public static function buildApplicationDataRecord(int $version, string $data): string
    {
        return self::buildRecord(ContentType::APPLICATION_DATA->value, $version, $data);
    }
    
    /**
     * 创建警告记录
     *
     * @param int $version TLS版本号
     * @param string $data 警告数据
     * @return string TLS警告记录二进制数据
     */
    public static function buildAlertRecord(int $version, string $data): string
    {
        return self::buildRecord(ContentType::ALERT->value, $version, $data);
    }
} 