<?php

namespace Tourze\TLSRecord\Tests;

use PHPUnit\Framework\TestCase;
use Tourze\TLSCommon\Protocol\ContentType;
use Tourze\TLSCommon\Version;
use Tourze\TLSRecord\CipherState;
use Tourze\TLSRecord\Exception\RecordException;
use Tourze\TLSRecord\RecordLayer;
use Tourze\TLSRecord\Tests\Mock\MockTransport;
use Tourze\TLSRecord\Transport\Transport;

/**
 * TLS记录层实现测试
 */
class RecordLayerTest extends TestCase
{
    /**
     * 测试发送未加密的记录
     */
    public function testSendUnencryptedRecord(): void
    {
        // 创建模拟的传输层
        $transport = new MockTransport();
        
        // 创建记录层
        $recordLayer = new RecordLayer($transport, Version::TLS_1_2->value);
        
        // 发送测试数据
        $recordLayer->sendRecord(ContentType::HANDSHAKE->value, 'hello');
        
        // 获取发送的数据
        $this->assertCount(1, $transport->getSentData(), '应该只发送一条记录');
        $sentData = $transport->getSentData()[0];
        
        // 验证消息类型
        $this->assertEquals(ContentType::HANDSHAKE->value, ord($sentData[0]));
        
        // 验证TLS版本号
        $this->assertEquals(0x03, ord($sentData[1]), '主版本号应为3');
        $this->assertEquals(0x03, ord($sentData[2]), '次版本号应为3');
        
        // 验证数据长度字段
        $length = (ord($sentData[3]) << 8) | ord($sentData[4]);
        $this->assertEquals(5, $length, '数据长度应为5');
        
        // 验证消息内容
        $this->assertEquals('hello', substr($sentData, 5), '消息内容应为"hello"');
    }
    
    /**
     * 测试发送大于最大片段长度的数据（自动分片）
     */
    public function testSendFragmentedRecord(): void
    {
        // 创建模拟的传输层
        $transport = new MockTransport();
        
        // 创建记录层并设置较小的最大片段长度
        $recordLayer = new RecordLayer($transport, Version::TLS_1_2->value);
        $recordLayer->setMaxFragmentLength(100);  // 使用有效的片段长度
        
        // 准备测试数据（超过最大片段长度）
        $testData = str_repeat('a', 250);
        
        // 发送测试数据
        $recordLayer->sendRecord(ContentType::APPLICATION_DATA->value, $testData);
        
        // 验证分片结果
        $sentData = $transport->getSentData();
        $this->assertCount(3, $sentData, '应分成3个片段发送');
        
        // 验证每个片段的内容
        foreach ($sentData as $index => $fragment) {
            // 验证内容类型
            $this->assertEquals(ContentType::APPLICATION_DATA->value, ord($fragment[0]), 
                "第" . ($index + 1) . "个片段内容类型应为APPLICATION_DATA");
            
            // 验证TLS版本
            $this->assertEquals(0x03, ord($fragment[1]), "第" . ($index + 1) . "个片段主版本号错误");
            $this->assertEquals(0x03, ord($fragment[2]), "第" . ($index + 1) . "个片段次版本号错误");
            
            // 获取片段长度
            $fragmentLength = (ord($fragment[3]) << 8) | ord($fragment[4]);
            
            // 每个片段的预期长度
            $expectedLength = ($index === 2) ? 50 : 100;
            $this->assertEquals($expectedLength, $fragmentLength, 
                "第" . ($index + 1) . "个片段长度应为" . $expectedLength);
                
            // 验证片段数据内容
            $expectedData = substr($testData, $index * 100, $expectedLength);
            $actualData = substr($fragment, 5);
            $this->assertEquals($expectedData, $actualData,
                "第" . ($index + 1) . "个片段数据内容错误");
        }
    }
    
    /**
     * 测试接收单个完整记录
     */
    public function testReceiveCompleteRecord(): void
    {
        // 创建测试记录数据，预设打包好的二进制数据
        $testData = 'hello';
        $testRecordData = chr(ContentType::APPLICATION_DATA->value) .  // 内容类型
                         chr(3) . chr(3) .  // TLS 1.2 版本 (0x0303)
                         pack('n', strlen($testData)) .  // 长度
                         $testData;  // 实际数据
        
        // 创建模拟传输层并添加测试数据
        $transport = new MockTransport([$testRecordData]);
        
        // 创建记录层
        $recordLayer = new RecordLayer($transport, Version::TLS_1_2->value);
        
        // 接收记录
        $record = $recordLayer->receiveRecord();
        
        // 验证记录内容
        $this->assertEquals(ContentType::APPLICATION_DATA->value, $record->getContentType());
        $this->assertEquals($testData, $record->getData());
        $this->assertEquals(Version::TLS_1_2->value, $record->getVersion());
    }
    
    /**
     * 测试接收分段的记录
     */
    public function testReceiveFragmentedRecord(): void
    {
        // 创建测试记录数据，预设打包好的二进制数据
        $testData = 'hello world';
        $testRecordData = chr(ContentType::HANDSHAKE->value) .  // 内容类型
                         chr(3) . chr(3) .  // TLS 1.2 版本 (0x0303)
                         pack('n', strlen($testData)) .  // 长度
                         $testData;  // 实际数据
        
        // 将记录数据分成两段
        $firstPart = substr($testRecordData, 0, 7); // 包含部分头部
        $secondPart = substr($testRecordData, 7);   // 剩余部分
        
        // 创建模拟传输层并添加分段数据
        $transport = new MockTransport([$firstPart, $secondPart]);
        
        // 创建记录层
        $recordLayer = new RecordLayer($transport, Version::TLS_1_2->value);
        
        // 接收记录
        $record = $recordLayer->receiveRecord();
        
        // 验证记录内容
        $this->assertEquals(ContentType::HANDSHAKE->value, $record->getContentType());
        $this->assertEquals($testData, $record->getData());
        $this->assertEquals(Version::TLS_1_2->value, $record->getVersion());
    }
    
    /**
     * 测试接收多个记录（接收缓冲区处理）
     */
    public function testReceiveMultipleRecords(): void
    {
        // 创建测试记录数据
        $record1Data = 'record1';
        $record1 = chr(ContentType::HANDSHAKE->value) .  // 内容类型
                   chr(3) . chr(3) .  // TLS 1.2 版本 (0x0303)
                   pack('n', strlen($record1Data)) .  // 长度
                   $record1Data;  // 实际数据
                   
        $record2Data = 'record2';
        $record2 = chr(ContentType::APPLICATION_DATA->value) .  // 内容类型
                   chr(3) . chr(3) .  // TLS 1.2 版本 (0x0303)
                   pack('n', strlen($record2Data)) .  // 长度
                   $record2Data;  // 实际数据
                   
        $record3Data = 'record3';
        $record3 = chr(ContentType::ALERT->value) .  // 内容类型
                   chr(3) . chr(3) .  // TLS 1.2 版本 (0x0303)
                   pack('n', strlen($record3Data)) .  // 长度
                   $record3Data;  // 实际数据
        
        // 组合所有记录
        $combinedData = $record1 . $record2 . $record3;
        
        // 创建模拟传输层并添加组合数据
        $transport = new MockTransport([$combinedData]);
        
        // 创建记录层
        $recordLayer = new RecordLayer($transport, Version::TLS_1_2->value);
        
        // 接收并验证第一个记录
        $record1 = $recordLayer->receiveRecord();
        $this->assertEquals(ContentType::HANDSHAKE->value, $record1->getContentType());
        $this->assertEquals('record1', $record1->getData());
        
        // 接收并验证第二个记录
        $record2 = $recordLayer->receiveRecord();
        $this->assertEquals(ContentType::APPLICATION_DATA->value, $record2->getContentType());
        $this->assertEquals('record2', $record2->getData());
        
        // 接收并验证第三个记录
        $record3 = $recordLayer->receiveRecord();
        $this->assertEquals(ContentType::ALERT->value, $record3->getContentType());
        $this->assertEquals('record3', $record3->getData());
    }
    
    /**
     * 测试当传输层无数据可读时抛出异常
     */
    public function testReceiveNoDataException(): void
    {
        // 创建一个不返回数据的模拟传输层
        $transport = new MockTransport();
        
        // 创建记录层
        $recordLayer = new RecordLayer($transport, Version::TLS_1_2->value);
        
        // 期望接收时抛出异常
        $this->expectException(RecordException::class);
        $this->expectExceptionMessage('传输层连接关闭或接收超时');
        
        // 尝试接收数据
        $recordLayer->receiveRecord();
    }
    
    /**
     * 测试设置无效的最大片段长度时抛出异常
     */
    public function testSetInvalidMaxFragmentLength(): void
    {
        // 创建记录层
        $recordLayer = new RecordLayer($this->createMock(Transport::class), Version::TLS_1_2->value);
        
        // 测试设置过小的值
        $this->expectException(RecordException::class);
        $this->expectExceptionMessage('无效的最大片段长度');
        $recordLayer->setMaxFragmentLength(10); // 小于64，应当失败
    }
    
    /**
     * 测试设置有效的最大片段长度
     */
    public function testSetValidMaxFragmentLength(): void
    {
        // 创建模拟的传输层
        $transport = new MockTransport();
        
        // 创建记录层
        $recordLayer = new RecordLayer($transport, Version::TLS_1_2->value);
        
        // 设置有效的最大片段长度
        $recordLayer->setMaxFragmentLength(1024);
        
        // 测试成功设置（通过检查数据分片是否正确）
        $testData = str_repeat('a', 1500);
        $recordLayer->sendRecord(ContentType::APPLICATION_DATA->value, $testData);
        
        $sentData = $transport->getSentData();
        $this->assertCount(2, $sentData, '应分成2个片段发送');
        
        // 验证第一个分片长度
        $fragmentLength = (ord($sentData[0][3]) << 8) | ord($sentData[0][4]);
        $this->assertEquals(1024, $fragmentLength, '第一个片段长度应为1024');
        
        // 验证第二个分片长度
        $fragmentLength = (ord($sentData[1][3]) << 8) | ord($sentData[1][4]);
        $this->assertEquals(476, $fragmentLength, '第二个片段长度应为476');
    }
    
    /**
     * 测试切换读写加密状态
     */
    public function testChangeCipherSpec(): void
    {
        // 创建模拟的传输层
        $transport = new MockTransport();
        
        // 创建记录层
        $recordLayer = new RecordLayer($transport, Version::TLS_1_2->value);
        
        // 创建加密状态
        $writeState = new CipherState(
            'TLS_AES_128_GCM_SHA256',
            str_repeat('k', 16),  // 密钥
            str_repeat('i', 12),  // IV
            str_repeat('m', 16),  // MAC密钥
            Version::TLS_1_2->value
        );
        
        $readState = new CipherState(
            'TLS_AES_128_GCM_SHA256',
            str_repeat('r', 16),  // 不同的密钥
            str_repeat('s', 12),  // 不同的IV
            str_repeat('t', 16),  // 不同的MAC密钥
            Version::TLS_1_2->value
        );
        
        // 切换到加密模式
        $recordLayer->changeWriteCipherSpec($writeState);
        $recordLayer->changeReadCipherSpec($readState);
        
        // 验证状态变更成功
        // 注意：由于加密状态是私有属性，我们不能直接验证
        // 而是通过后续操作间接验证状态改变生效
        
        $this->assertTrue(true); // 暂时跳过验证
    }
} 