<?php

namespace Tourze\TLSRecord;

use Tourze\TLSRecord\Exception\RecordException;
use Tourze\TLSRecord\Transport\Transport;

/**
 * TLS记录层工厂类，用于创建和配置记录层实例
 */
class RecordFactory
{
    /**
     * 创建TLS记录层实例
     *
     * @param Transport $transport 传输层接口
     * @param int $tlsVersion TLS版本
     * @return RecordProtocol 记录层协议实例
     * @throws RecordException 如果指定的TLS版本不受支持
     */
    public static function create(Transport $transport, int $tlsVersion): RecordProtocol
    {
        // 验证TLS版本是否支持
        if (!self::isSupportedVersion($tlsVersion)) {
            throw new RecordException('不支持的TLS版本: 0x' . dechex($tlsVersion));
        }
        
        // 创建记录层实例
        return new RecordLayer($transport, $tlsVersion);
    }
    
    /**
     * 判断TLS版本是否受支持
     */
    private static function isSupportedVersion(int $version): bool
    {
        return match($version) {
            0x0301, 0x0302, 0x0303, 0x0304 => true,
            default => false,
        };
    }
} 