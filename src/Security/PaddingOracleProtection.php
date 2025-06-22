<?php

namespace Tourze\TLSRecord\Security;

use Tourze\TLSCommon\Version;

/**
 * 防御填充预言攻击（如BEAST、POODLE）的实用工具类
 */
class PaddingOracleProtection
{
    /**
     * CBC模式下应用分割记录技术来防御BEAST攻击
     *
     * BEAST攻击利用CBC模式的特性，通过使攻击者控制的数据与密文互相影响
     * 分割记录技术将每条记录分割成单字节和剩余字节两部分，减少攻击面
     *
     * @param string $plaintext 原始明文
     * @return array 分割后的明文块数组
     */
    public static function applySplitRecordMitigation(string $plaintext): array
    {
        // 如果数据长度小于2个字节，不需要分割
        if (strlen($plaintext) < 2) {
            return [$plaintext];
        }
        
        // 将第一个字节作为单独记录，其余字节作为另一个记录
        return [
            substr($plaintext, 0, 1),
            substr($plaintext, 1)
        ];
    }
    
    /**
     * 对填充数据进行恒定时间验证，防止时序攻击
     *
     * @param string $data 需要验证填充的数据
     * @param int $blockSize 块大小
     * @return array 验证结果[是否有效, 填充长度]
     */
    public static function verifyPaddingConstantTime(string $data, int $blockSize): array
    {
        $length = strlen($data);
        
        // 如果数据长度小于块大小，填充无效
        if ($length === 0 || $length % $blockSize !== 0) {
            return [false, 0];
        }
        
        // 获取填充值（最后一个字节）
        $paddingValue = ord($data[$length - 1]);
        
        // 如果填充值大于块大小，无效
        if ($paddingValue >= $blockSize) {
            return [false, 0];
        }
        
        // 检查填充值是否有效（所有填充字节应该等于填充值）
        $valid = 1; // 假设有效
        
        // 使用恒定时间比较所有可能的填充字节
        for ($i = 0; $i < $blockSize; $i++) {
            $checkIndex = $length - 1 - $i;
            
            // 如果检查的位置超出了数据范围，跳过
            if ($checkIndex < 0) {
                continue;
            }
            
            // 检查是否应该是填充字节
            $isPaddingPosition = ($i < $paddingValue) ? 1 : 0;
            
            // 检查字节值是否等于填充值
            $isCorrectValue = (ord($data[$checkIndex]) === $paddingValue) ? 1 : 0;
            
            // 只有当位置是填充位置且值不正确时才设置valid为0
            // 使用按位运算保持时间恒定
            $valid &= ($isPaddingPosition & $isCorrectValue) | (1 - $isPaddingPosition);
        }
        
        return [$valid === 1, $paddingValue + 1];
    }
    
    /**
     * 根据TLS版本和密码套件选择合适的防御策略
     *
     * @param int $tlsVersion TLS版本
     * @param string $cipherSuite 加密套件
     * @return string 推荐的防御策略
     */
    public static function selectProtectionStrategy(int $tlsVersion, string $cipherSuite): string
    {
        // TLS 1.3不受填充预言攻击影响，使用AEAD加密
        if ($tlsVersion >= Version::TLS_1_3->value) {
            return 'none';
        }
        
        // 检查是否使用CBC模式（可能受BEAST/POODLE影响）
        if (strpos($cipherSuite, 'CBC') !== false) {
            // TLS 1.0容易受到BEAST攻击
            if ($tlsVersion === Version::TLS_1_0->value) {
                return 'split_records';
            }
            
            // TLS 1.1和TLS 1.2可能受到POODLE攻击
            return 'constant_time_padding';
        }
        
        // 对于GCM、CCM或ChaCha20-Poly1305等AEAD密码套件
        if (strpos($cipherSuite, 'GCM') !== false || 
            strpos($cipherSuite, 'CCM') !== false || 
            strpos($cipherSuite, 'CHACHA20_POLY1305') !== false) {
            return 'none';
        }
        
        // 默认采取保守策略
        return 'constant_time_padding';
    }
    
    /**
     * 对明文应用标准PKCS#7填充
     *
     * @param string $plaintext 需要填充的明文
     * @param int $blockSize 块大小
     * @return string 填充后的明文
     */
    public static function applyPKCS7Padding(string $plaintext, int $blockSize): string
    {
        $paddingLength = $blockSize - (strlen($plaintext) % $blockSize);
        
        // PKCS#7填充：每个填充字节的值等于填充的长度
        $padding = str_repeat(chr($paddingLength), $paddingLength);
        
        return $plaintext . $padding;
    }
    
    /**
     * 移除PKCS#7填充，使用恒定时间实现
     *
     * @param string $paddedData 带填充的数据
     * @param int $blockSize 块大小
     * @return string|null 成功时返回移除填充的数据，失败返回null
     */
    public static function removePKCS7Padding(string $paddedData, int $blockSize): ?string
    {
        // 验证填充
        [$isValid, $paddingLength] = self::verifyPaddingConstantTime($paddedData, $blockSize);
        
        if (!$isValid) {
            return null;
        }
        
        // 移除填充
        return substr($paddedData, 0, -$paddingLength);
    }
}
