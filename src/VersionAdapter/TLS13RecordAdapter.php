<?php

namespace Tourze\TLSRecord\VersionAdapter;

use Tourze\TLSCommon\Protocol\ContentType;
use Tourze\TLSCryptoFactory\CryptoFactory;
use Tourze\TLSCryptoSymmetric\Exception\CipherException;
use Tourze\TLSRecord\CipherState;
use Tourze\TLSRecord\Exception\RecordException;
use Tourze\TLSRecord\RecordData;

/**
 * TLS 1.3记录层适配器实现
 */
class TLS13RecordAdapter implements RecordVersionAdapter
{
    /**
     * TLS记录头部长度（类型1字节 + 版本2字节 + 长度2字节）
     */
    private const RECORD_HEADER_LENGTH = 5;
    
    /**
     * 将记录数据编码为TLS 1.3二进制格式
     */
    public function encodeRecord(RecordData $record): string
    {
        $contentType = $record->getContentType();
        $data = $record->getData();
        
        // TLS 1.3始终使用TLS 1.2的版本号来保持兼容性
        $version = 0x0303; // TLS 1.2
        
        // 构造记录头部
        $header = pack(
            'CCC',
            $contentType,
            ($version >> 8) & 0xFF,  // 主版本
            $version & 0xFF           // 次版本
        );
        
        // 添加长度字段
        $header .= pack('n', strlen($data));
        
        // 组合头部和数据
        return $header . $data;
    }
    
    /**
     * 从二进制数据解码TLS 1.3记录
     */
    public function decodeRecord(string $data): RecordData
    {
        // 确保数据至少包含一个完整的记录头
        if (strlen($data) < self::RECORD_HEADER_LENGTH) {
            throw new RecordException('记录数据不完整：头部长度不足');
        }
        
        // 解析记录头
        $header = unpack('Ctype/Cmajor/Cminor/nlength', $data);
        
        // 检查记录长度
        $recordLength = $header['length'];
        $totalLength = self::RECORD_HEADER_LENGTH + $recordLength;
        
        if (strlen($data) < $totalLength) {
            throw new RecordException('记录数据不完整：内容长度不足');
        }
        
        // 提取记录内容
        $content = substr($data, self::RECORD_HEADER_LENGTH, $recordLength);
        
        // 构建版本
        $version = ($header['major'] << 8) | $header['minor'];
        
        // 返回记录数据
        return new RecordData($header['type'], $content, $version);
    }
    
    /**
     * 对明文数据应用TLS 1.3加密（AEAD模式）
     */
    public function applyEncryption(string $plaintext, CipherState $state, int $contentType): string
    {
        // 在TLS 1.3中，内容类型会被加入到明文末尾，并且整体加密
        $plaintextWithType = $plaintext . chr($contentType);
        
        // 获取序列号并转换为随机数（nonce）
        $seqNum = $state->getAndIncrementSequenceNumber();
        $nonce = $this->deriveNonce($seqNum, $state->getIV());
        
        // 构建附加数据（仅用于验证，不加密）
        $additionalData = $this->buildAdditionalData(strlen($plaintextWithType));
        
        try {
            // 从CipherState中获取密码套件信息
            $cipherSuite = $state->getCipherSuite();
            // 解析密码套件以确定加密算法，通常AES-GCM或ChaCha20-Poly1305
            $algorithmName = $this->getAlgorithmFromCipherSuite($cipherSuite);
            
            // 使用tls-crypto包创建适当的加密实例
            $cipher = CryptoFactory::createCipher($algorithmName);
            
            // 获取密钥并执行AEAD加密
            $key = $state->getKey();
            $tag = '';
            $ciphertext = $cipher->encrypt($plaintextWithType, $key, $nonce, $additionalData, $tag);
            
            // 合并密文和认证标签
            $encryptedData = $ciphertext . $tag;
            
            // 在加密后，内容类型统一为application_data
            return $encryptedData;
        } catch (CipherException $e) {
            throw new RecordException('TLS 1.3加密失败: ' . $e->getMessage(), 0, $e);
        }
    }
    
    /**
     * 对密文数据应用TLS 1.3解密
     */
    public function applyDecryption(string $ciphertext, CipherState $state): array
    {
        // 获取序列号并转换为随机数（nonce）
        $seqNum = $state->getAndIncrementSequenceNumber();
        $nonce = $this->deriveNonce($seqNum, $state->getIV());
        
        // 构建附加数据
        $additionalData = $this->buildAdditionalData(strlen($ciphertext) - 16); // 减去16字节的认证标签
        
        try {
            // 从CipherState中获取密码套件信息
            $cipherSuite = $state->getCipherSuite();
            // 解析密码套件以确定加密算法
            $algorithmName = $this->getAlgorithmFromCipherSuite($cipherSuite);
            
            // 使用tls-crypto包创建适当的加密实例
            $cipher = CryptoFactory::createCipher($algorithmName);
            
            // 分离密文和认证标签
            $actualCiphertext = substr($ciphertext, 0, -16);
            $tag = substr($ciphertext, -16);
            
            // 获取密钥并执行AEAD解密
            $key = $state->getKey();
            $decryptedData = $cipher->decrypt($actualCiphertext, $key, $nonce, $additionalData, $tag);
            
            // 提取原始内容类型（存储在解密数据的最后一个字节）
            $length = strlen($decryptedData);
            if ($length === 0) {
                throw new RecordException('解密数据为空');
            }
            
            $originalContentType = ord($decryptedData[$length - 1]);
            $plaintext = substr($decryptedData, 0, -1);
            
            return [$plaintext, $originalContentType];
        } catch (CipherException $e) {
            throw new RecordException('TLS 1.3解密失败: ' . $e->getMessage(), 0, $e);
        }
    }
    
    /**
     * 从序列号和初始IV派生随机数（nonce）
     */
    private function deriveNonce(int $seqNum, string $iv): string
    {
        // TLS 1.3的nonce是通过将序列号与IV进行XOR操作得到的
        $seqNumBytes = pack('J', $seqNum); // 64位序列号
        
        $nonce = '';
        for ($i = 0; $i < strlen($iv); $i++) {
            $bytePos = $i % 8;
            $nonce .= chr(ord($iv[$i]) ^ ord($seqNumBytes[$bytePos]));
        }
        
        return $nonce;
    }
    
    /**
     * 构建AEAD模式使用的附加数据
     */
    private function buildAdditionalData(int $contentLength): string
    {
        // TLS 1.3中的附加数据是一个TLS 1.3记录头
        // 类型固定为application_data
        // 版本固定为TLS 1.2（0x0303）
        // 长度为明文长度
        return pack(
            'CCCn',
            ContentType::APPLICATION_DATA->value,
            0x03, // TLS主版本
            0x03, // TLS次版本
            $contentLength
        );
    }
    
    /**
     * 从密码套件标识符中提取加密算法名称
     */
    private function getAlgorithmFromCipherSuite(string $cipherSuite): string
    {
        // 此处应根据密码套件标识符确定具体的加密算法
        // TLS 1.3只支持5种密码套件，都使用AEAD算法

        if (strpos($cipherSuite, 'AES_128_GCM') !== false) {
            return 'aes-128-gcm';
        } elseif (strpos($cipherSuite, 'AES_256_GCM') !== false) {
            return 'aes-256-gcm';
        } elseif (strpos($cipherSuite, 'CHACHA20_POLY1305') !== false) {
            return 'chacha20-poly1305';
        }
        
        // 默认使用AES-256-GCM
        return 'aes-256-gcm';
    }
}
