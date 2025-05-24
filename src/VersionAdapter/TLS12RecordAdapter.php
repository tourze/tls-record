<?php

namespace Tourze\TLSRecord\VersionAdapter;

use Tourze\TLSCommon\Protocol\ContentType;
use Tourze\TLSCryptoFactory\CryptoFactory;
use Tourze\TLSCryptoHash\Exception\MacException;
use Tourze\TLSCryptoSymmetric\Exception\CipherException;
use Tourze\TLSRecord\CipherState;
use Tourze\TLSRecord\Exception\RecordException;
use Tourze\TLSRecord\RecordData;
use Tourze\TLSRecord\Security\PaddingOracleProtection;

/**
 * TLS 1.2记录层适配器实现
 */
class TLS12RecordAdapter implements RecordVersionAdapter
{
    /**
     * TLS记录头部长度（类型1字节 + 版本2字节 + 长度2字节）
     */
    private const RECORD_HEADER_LENGTH = 5;

    /**
     * 将记录数据编码为TLS 1.2二进制格式
     */
    public function encodeRecord(RecordData $record): string
    {
        $contentType = $record->getContentType();
        $data = $record->getData();
        $version = $record->getVersion() ?? 0x0303; // 默认为TLS 1.2

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
     * 从二进制数据解码TLS 1.2记录
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
     * 对明文数据应用TLS 1.2加密（MAC-then-Encrypt模式）
     */
    public function applyEncryption(string $plaintext, CipherState $state, int $contentType): string
    {
        try {
            // 获取加密套件和TLS版本信息
            $cipherSuite = $state->getCipherSuite();
            $tlsVersion = $state->getTLSVersion();

            // 获取序列号
            $seqNum = $state->getAndIncrementSequenceNumber();

            // 选择合适的防御策略
            $protectionStrategy = PaddingOracleProtection::selectProtectionStrategy($tlsVersion, $cipherSuite);

            // 如果使用分割记录策略（防御BEAST攻击），分割明文
            if ($protectionStrategy === 'split_records' && strpos($cipherSuite, 'CBC') !== false) {
                // 注意：此处仅展示策略，实际应用应在RecordLayer层处理分割
                // 在此处我们仍然处理单个记录
            }

            // 使用tls-crypto包计算MAC
            $mac = $this->calculateMAC($state, $seqNum, $contentType, $plaintext);

            // 添加MAC到明文
            $dataWithMAC = $plaintext . $mac;

            // 确定加密算法类型（AEAD、CBC等）
            if (strpos($cipherSuite, 'GCM') !== false ||
                strpos($cipherSuite, 'CCM') !== false ||
                strpos($cipherSuite, 'CHACHA20_POLY1305') !== false) {
                // AEAD模式加密
                return $this->encryptAEAD($dataWithMAC, $state, $contentType, $seqNum);
            } else {
                // CBC或其他模式加密
                // 添加填充（对于块密码如AES-CBC）
                $blockSize = $this->getBlockSizeFromCipherSuite($cipherSuite);
                $paddedData = PaddingOracleProtection::applyPKCS7Padding($dataWithMAC, $blockSize);

                // 使用tls-crypto包加密数据
                return $this->encryptCBC($paddedData, $state);
            }
        } catch (\Exception $e) {
            throw new RecordException('加密失败: ' . $e->getMessage(), 0, $e);
        }
    }

    /**
     * 对密文数据应用TLS 1.2解密
     */
    public function applyDecryption(string $ciphertext, CipherState $state): array
    {
        try {
            // 获取加密套件和TLS版本信息
            $cipherSuite = $state->getCipherSuite();
            $tlsVersion = $state->getTLSVersion();

            // 获取序列号
            $seqNum = $state->getSequenceNumber();

            // 确定加密算法类型（AEAD、CBC等）
            if (strpos($cipherSuite, 'GCM') !== false ||
                strpos($cipherSuite, 'CCM') !== false ||
                strpos($cipherSuite, 'CHACHA20_POLY1305') !== false) {
                // AEAD模式解密
                $dataWithMAC = $this->decryptAEAD($ciphertext, $state, ContentType::APPLICATION_DATA->value, $seqNum);
                // AEAD已经验证了完整性，不需要再次验证MAC
                $state->getAndIncrementSequenceNumber(); // 递增序列号
                return [$dataWithMAC, ContentType::APPLICATION_DATA->value];
            } else {
                // CBC或其他模式解密
                $decryptedData = $this->decryptCBC($ciphertext, $state);

                // 移除填充
                $blockSize = $this->getBlockSizeFromCipherSuite($cipherSuite);
                $dataWithMAC = PaddingOracleProtection::removePKCS7Padding($decryptedData, $blockSize);

                if ($dataWithMAC === null) {
                    throw new RecordException('填充验证失败');
                }

                // 分离数据和MAC
                $macLength = $this->getMacLengthFromCipherSuite($cipherSuite);

                if (strlen($dataWithMAC) < $macLength) {
                    throw new RecordException('解密数据长度不足，无法提取MAC');
                }

                $plaintext = substr($dataWithMAC, 0, -$macLength);
                $receivedMAC = substr($dataWithMAC, -$macLength);

                // 验证MAC
                $calculatedMAC = $this->calculateMAC($state, $seqNum, ContentType::APPLICATION_DATA->value, $plaintext);
                $state->getAndIncrementSequenceNumber(); // 递增序列号

                if (!hash_equals($receivedMAC, $calculatedMAC)) {
                    throw new RecordException('MAC验证失败');
                }

                return [$plaintext, ContentType::APPLICATION_DATA->value];
            }
        } catch (\Exception $e) {
            throw new RecordException('解密失败: ' . $e->getMessage(), 0, $e);
        }
    }

    /**
     * 计算MAC（消息认证码）
     */
    private function calculateMAC(CipherState $state, int $seqNum, int $contentType, string $data): string
    {
        try {
            // 从密码套件获取MAC算法名称
            $macAlgorithm = $this->getMacAlgorithmFromCipherSuite($state->getCipherSuite());

            // 使用tls-crypto包创建MAC实例
            $mac = CryptoFactory::createMac($macAlgorithm);

            // 构造MAC输入
            $seqNumBytes = pack('J', $seqNum); // 64位序列号
            $headerBytes = pack('Cnn', $contentType, $state->getTLSVersion() >> 8, $state->getTLSVersion() & 0xFF);
            $lengthBytes = pack('n', strlen($data));

            $macInput = $seqNumBytes . $headerBytes . $lengthBytes . $data;

            // 计算MAC
            return $mac->compute($macInput, $state->getMacKey());
        } catch (MacException $e) {
            throw new RecordException('MAC计算失败: ' . $e->getMessage(), 0, $e);
        }
    }

    /**
     * 使用CBC模式加密数据
     */
    private function encryptCBC(string $data, CipherState $state): string
    {
        try {
            // 解析密码套件以确定加密算法
            $algorithmName = $this->getCipherAlgorithmFromCipherSuite($state->getCipherSuite());

            // 使用tls-crypto包创建适当的加密实例
            $cipher = CryptoFactory::createCipher($algorithmName);

            // 获取密钥和IV
            $key = $state->getKey();
            $iv = $state->getIV();

            // 执行加密
            return $cipher->encrypt($data, $key, $iv);
        } catch (CipherException $e) {
            throw new RecordException('CBC加密失败: ' . $e->getMessage(), 0, $e);
        }
    }

    /**
     * 使用CBC模式解密数据
     */
    private function decryptCBC(string $data, CipherState $state): string
    {
        try {
            // 解析密码套件以确定加密算法
            $algorithmName = $this->getCipherAlgorithmFromCipherSuite($state->getCipherSuite());

            // 使用tls-crypto包创建适当的加密实例
            $cipher = CryptoFactory::createCipher($algorithmName);

            // 获取密钥和IV
            $key = $state->getKey();
            $iv = $state->getIV();

            // 执行解密
            return $cipher->decrypt($data, $key, $iv);
        } catch (CipherException $e) {
            throw new RecordException('CBC解密失败: ' . $e->getMessage(), 0, $e);
        }
    }

    /**
     * 使用AEAD模式加密数据
     */
    private function encryptAEAD(string $data, CipherState $state, int $contentType, int $seqNum): string
    {
        try {
            // 解析密码套件以确定加密算法
            $algorithmName = $this->getCipherAlgorithmFromCipherSuite($state->getCipherSuite());

            // 使用tls-crypto包创建适当的加密实例
            $cipher = CryptoFactory::createCipher($algorithmName);

            // 获取密钥
            $key = $state->getKey();

            // 构造nonce
            $nonce = $this->deriveAEADNonce($seqNum, $state->getIV());

            // 构造附加数据
            $additionalData = $this->buildAEADAdditionalData($state->getTLSVersion(), $contentType, strlen($data));

            // 执行AEAD加密
            $tag = '';
            $ciphertext = $cipher->encrypt($data, $key, $nonce, $additionalData, $tag);

            // 返回密文和认证标签的组合
            return $ciphertext . $tag;
        } catch (CipherException $e) {
            throw new RecordException('AEAD加密失败: ' . $e->getMessage(), 0, $e);
        }
    }

    /**
     * 使用AEAD模式解密数据
     */
    private function decryptAEAD(string $data, CipherState $state, int $contentType, int $seqNum): string
    {
        try {
            // 解析密码套件以确定加密算法
            $algorithmName = $this->getCipherAlgorithmFromCipherSuite($state->getCipherSuite());

            // 使用tls-crypto包创建适当的加密实例
            $cipher = CryptoFactory::createCipher($algorithmName);

            // 获取密钥
            $key = $state->getKey();

            // 构造nonce
            $nonce = $this->deriveAEADNonce($seqNum, $state->getIV());

            // 分离密文和认证标签
            $tagLength = 16; // GCM和ChaCha20-Poly1305的标签长度都是16字节
            $ciphertext = substr($data, 0, -$tagLength);
            $tag = substr($data, -$tagLength);

            // 构造附加数据
            $additionalData = $this->buildAEADAdditionalData($state->getTLSVersion(), $contentType, strlen($ciphertext));

            // 执行AEAD解密
            return $cipher->decrypt($ciphertext, $key, $nonce, $additionalData, $tag);
        } catch (CipherException $e) {
            throw new RecordException('AEAD解密失败: ' . $e->getMessage(), 0, $e);
        }
    }

    /**
     * 为AEAD模式派生nonce
     */
    private function deriveAEADNonce(int $seqNum, string $iv): string
    {
        // TLS 1.2的AEAD nonce是通过将序列号与IV进行XOR操作得到的
        // 与TLS 1.3类似，但细节可能有所不同
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
    private function buildAEADAdditionalData(int $tlsVersion, int $contentType, int $contentLength): string
    {
        // TLS 1.2中的附加数据是序列号、记录头和长度的组合
        return pack(
            'CCCn',
            $contentType,
            ($tlsVersion >> 8) & 0xFF,
            $tlsVersion & 0xFF,
            $contentLength
        );
    }

    /**
     * 从密码套件中获取MAC算法名称
     */
    private function getMacAlgorithmFromCipherSuite(string $cipherSuite): string
    {
        // 解析密码套件以确定MAC算法
        if (strpos($cipherSuite, 'SHA384') !== false) {
            return 'hmac-sha384';
        } elseif (strpos($cipherSuite, 'SHA256') !== false) {
            return 'hmac-sha256';
        } else {
            return 'hmac-sha1'; // 默认
        }
    }

    /**
     * 从密码套件中获取MAC长度
     */
    private function getMacLengthFromCipherSuite(string $cipherSuite): int
    {
        // 根据MAC算法确定长度
        if (strpos($cipherSuite, 'SHA384') !== false) {
            return 48; // SHA384 输出48字节
        } elseif (strpos($cipherSuite, 'SHA256') !== false) {
            return 32; // SHA256 输出32字节
        } else {
            return 20; // SHA1 输出20字节
        }
    }

    /**
     * 从密码套件中获取加密算法名称
     */
    private function getCipherAlgorithmFromCipherSuite(string $cipherSuite): string
    {
        if (strpos($cipherSuite, 'AES_128_GCM') !== false) {
            return 'aes-128-gcm';
        } elseif (strpos($cipherSuite, 'AES_256_GCM') !== false) {
            return 'aes-256-gcm';
        } elseif (strpos($cipherSuite, 'AES_128_CCM') !== false) {
            return 'aes-128-ccm';
        } elseif (strpos($cipherSuite, 'AES_128_CBC') !== false) {
            return 'aes-128-cbc';
        } elseif (strpos($cipherSuite, 'AES_256_CBC') !== false) {
            return 'aes-256-cbc';
        } elseif (strpos($cipherSuite, 'CHACHA20_POLY1305') !== false) {
            return 'chacha20-poly1305';
        }

        // 默认使用AES-128-CBC
        return 'aes-128-cbc';
    }

    /**
     * 从密码套件中获取块大小
     */
    private function getBlockSizeFromCipherSuite(string $cipherSuite): int
    {
        // AES的块大小都是16字节
        if (strpos($cipherSuite, 'AES') !== false) {
            return 16;
        } elseif (strpos($cipherSuite, '3DES') !== false) {
            return 8; // 3DES的块大小是8字节
        }

        // 默认返回16
        return 16;
    }
}
