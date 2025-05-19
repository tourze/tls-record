<?php

namespace Tourze\TLSRecord;

use Tourze\TLSCommon\Protocol\ContentType;
use Tourze\TLSCommon\Version;
use Tourze\TLSRecord\Exception\RecordException;
use Tourze\TLSRecord\Security\ReplayProtection;
use Tourze\TLSRecord\Transport\Transport;
use Tourze\TLSRecord\VersionAdapter\RecordVersionAdapter;
use Tourze\TLSRecord\VersionAdapter\TLS12RecordAdapter;
use Tourze\TLSRecord\VersionAdapter\TLS13RecordAdapter;

/**
 * TLS记录层实现类
 */
class RecordLayer implements RecordProtocol
{
    /**
     * 默认最大片段长度
     */
    private const DEFAULT_MAX_FRAGMENT_LENGTH = 16384;
    
    /**
     * 记录层状态常量 - 未加密
     */
    private const STATE_PLAIN = 0;
    
    /**
     * 记录层状态常量 - 已加密
     */
    private const STATE_ENCRYPTED = 1;
    
    /**
     * 读取方向的状态
     */
    private int $readState = self::STATE_PLAIN;
    
    /**
     * 写入方向的状态
     */
    private int $writeState = self::STATE_PLAIN;
    
    /**
     * 读取方向的加密状态
     */
    private ?CipherState $readCipherState = null;
    
    /**
     * 写入方向的加密状态
     */
    private ?CipherState $writeCipherState = null;
    
    /**
     * 最大片段长度
     */
    private int $maxFragmentLength = self::DEFAULT_MAX_FRAGMENT_LENGTH;
    
    /**
     * 记录版本适配器
     */
    private RecordVersionAdapter $versionAdapter;
    
    /**
     * 接收缓冲区
     */
    private string $receiveBuffer = '';
    
    /**
     * 防重放保护
     */
    private ReplayProtection $replayProtection;
    
    /**
     * 是否启用防重放保护
     */
    private bool $replayProtectionEnabled = false;
    
    /**
     * 构造函数
     *
     * @param Transport $transport 传输层接口
     * @param int $tlsVersion TLS版本
     * @param bool $enableReplayProtection 是否启用防重放保护
     */
    public function __construct(
        private readonly Transport $transport,
        private readonly int $tlsVersion,
        bool $enableReplayProtection = true
    ) {
        // 根据TLS版本选择适当的适配器
        $this->versionAdapter = $this->createVersionAdapter($tlsVersion);
        
        // 初始化防重放保护
        $this->replayProtection = new ReplayProtection();
        $this->replayProtectionEnabled = $enableReplayProtection;
    }
    
    /**
     * 创建适合当前TLS版本的记录适配器
     */
    private function createVersionAdapter(int $tlsVersion): RecordVersionAdapter
    {
        return match($tlsVersion) {
            Version::TLS_1_3->value => new TLS13RecordAdapter(),
            default => new TLS12RecordAdapter(),
        };
    }
    
    /**
     * 发送TLS记录
     */
    public function sendRecord(int $contentType, string $data): void
    {
        // 如果数据超过最大片段长度，分片发送
        if (strlen($data) > $this->maxFragmentLength) {
            for ($offset = 0; $offset < strlen($data); $offset += $this->maxFragmentLength) {
                $fragment = substr($data, $offset, $this->maxFragmentLength);
                $this->sendSingleRecord($contentType, $fragment);
            }
        } else {
            $this->sendSingleRecord($contentType, $data);
        }
    }
    
    /**
     * 发送单个TLS记录
     */
    private function sendSingleRecord(int $contentType, string $data): void
    {
        // 创建记录数据对象
        $record = new RecordData($contentType, $data, $this->tlsVersion);
        
        // 处理加密状态
        if ($this->writeState === self::STATE_ENCRYPTED && $this->writeCipherState !== null) {
            // 加密数据
            $encryptedData = $this->versionAdapter->applyEncryption(
                $data, 
                $this->writeCipherState, 
                $contentType
            );
            
            // 在TLS 1.3中，加密后的记录内容类型始终为application_data
            $actualContentType = ($this->tlsVersion === Version::TLS_1_3->value) 
                ? ContentType::APPLICATION_DATA->value 
                : $contentType;
                
            $record = new RecordData($actualContentType, $encryptedData, $this->tlsVersion);
        }
        
        // 编码记录
        $encodedRecord = $this->versionAdapter->encodeRecord($record);
        
        // 发送到传输层
        $bytesSent = $this->transport->send($encodedRecord);
        
        if ($bytesSent !== strlen($encodedRecord)) {
            throw new RecordException('记录发送不完整，已发送' . $bytesSent . '字节，总共' . strlen($encodedRecord) . '字节');
        }
    }
    
    /**
     * 接收TLS记录
     */
    public function receiveRecord(): RecordData
    {
        // 尝试从接收缓冲区中解析一个完整的记录
        $record = $this->tryParseRecordFromBuffer();
        
        // 如果没有完整记录，则从传输层读取更多数据
        while ($record === null) {
            // 至少读取5字节（记录头部长度）
            $headerData = $this->receiveAtLeast(self::DEFAULT_MAX_FRAGMENT_LENGTH);
            
            if (empty($headerData)) {
                throw new RecordException('无法从传输层读取数据');
            }
            
            // 将新读取的数据添加到缓冲区
            $this->receiveBuffer .= $headerData;
            
            // 再次尝试解析记录
            $record = $this->tryParseRecordFromBuffer();
        }
        
        // 处理解密（如果需要）
        if ($this->readState === self::STATE_ENCRYPTED && $this->readCipherState !== null) {
            try {
                // 如果启用了防重放保护，检查序列号
                if ($this->replayProtectionEnabled) {
                    $seqNum = $this->readCipherState->getSequenceNumber();
                    if ($this->replayProtection->isReplay($seqNum)) {
                        throw new RecordException('检测到重放攻击尝试：序列号 ' . $seqNum . ' 已被处理');
                    }
                }
                
                // 解密数据并获取原始内容类型
                [$plaintext, $originalContentType] = $this->versionAdapter->applyDecryption(
                    $record->getData(),
                    $this->readCipherState
                );
                
                // 如果启用了防重放保护，标记序列号为已处理
                if ($this->replayProtectionEnabled) {
                    $this->replayProtection->markAsProcessed($this->readCipherState->getSequenceNumber() - 1);
                }
                
                // 创建包含解密数据和原始内容类型的新记录
                $record = new RecordData($originalContentType, $plaintext, $record->getVersion());
            } catch (RecordException $e) {
                // 如果是记录格式错误或MAC验证失败，可能是攻击尝试
                if (strpos($e->getMessage(), 'MAC验证失败') !== false || 
                    strpos($e->getMessage(), '解密失败') !== false) {
                    // 记录详细错误，但使用通用错误消息返回，避免信息泄露
                    // 这里应该添加日志记录
                    throw new RecordException('记录验证失败', 0, $e);
                }
                
                // 其他错误直接抛出
                throw $e;
            }
        }
        
        return $record;
    }
    
    /**
     * 从接收缓冲区中尝试解析一个完整的记录
     */
    private function tryParseRecordFromBuffer(): ?RecordData
    {
        // 如果缓冲区中没有足够的数据来解析记录头部，返回null
        if (strlen($this->receiveBuffer) < 5) {
            return null;
        }
        
        // 先解析头部，获取记录长度
        $header = unpack('Ctype/Cmajor/Cminor/nlength', substr($this->receiveBuffer, 0, 5));
        $recordLength = $header['length'];
        $totalLength = 5 + $recordLength;
        
        // 如果缓冲区中没有完整的记录，返回null
        if (strlen($this->receiveBuffer) < $totalLength) {
            return null;
        }
        
        // 提取完整记录数据
        $recordData = substr($this->receiveBuffer, 0, $totalLength);
        
        // 从缓冲区中移除已处理的数据
        $this->receiveBuffer = substr($this->receiveBuffer, $totalLength);
        
        // 解码记录
        try {
            return $this->versionAdapter->decodeRecord($recordData);
        } catch (RecordException $e) {
            // 如果解码失败，可能是记录格式错误或者是攻击尝试
            // 清空缓冲区以避免潜在的DoS攻击
            $this->receiveBuffer = '';
            throw $e;
        }
    }
    
    /**
     * 从传输层接收至少指定字节数的数据
     */
    private function receiveAtLeast(int $minBytes): string
    {
        $data = $this->transport->receive($minBytes);

        // 如果没有接收到数据，可能是连接关闭或超时
        if (empty($data)) {
            throw new RecordException('传输层连接关闭或接收超时');
        }

        return $data;
    }

    /**
     * 切换到加密状态（写入方向）
     */
    public function changeWriteCipherSpec(CipherState $state): void
    {
        $this->writeCipherState = $state;
        $this->writeState = self::STATE_ENCRYPTED;
    }
    
    /**
     * 切换到加密状态（读取方向）
     */
    public function changeReadCipherSpec(CipherState $state): void
    {
        $this->readCipherState = $state;
        $this->readState = self::STATE_ENCRYPTED;
        
        // 重置防重放保护
        if ($this->replayProtectionEnabled) {
            $this->replayProtection->reset();
        }
    }
    
    /**
     * 设置最大片段长度
     */
    public function setMaxFragmentLength(int $length): void
    {
        if ($length < 64 || $length > 16384) {
            throw new RecordException('无效的最大片段长度，有效范围为64-16384');
        }
        
        $this->maxFragmentLength = $length;
    }
    
    /**
     * 启用或禁用防重放保护
     */
    public function setReplayProtection(bool $enabled): void
    {
        $this->replayProtectionEnabled = $enabled;
        
        if ($enabled) {
            $this->replayProtection->reset();
        }
    }
    
    /**
     * 获取防重放保护状态
     */
    public function isReplayProtectionEnabled(): bool
    {
        return $this->replayProtectionEnabled;
    }
}
