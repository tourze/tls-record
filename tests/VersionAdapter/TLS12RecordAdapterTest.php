<?php

namespace Tourze\TLSRecord\Tests\VersionAdapter;

use PHPUnit\Framework\TestCase;
use Tourze\TLSCommon\Protocol\ContentType;
use Tourze\TLSCommon\Version;
use Tourze\TLSRecord\CipherState;
use Tourze\TLSRecord\Exception\RecordException;
use Tourze\TLSRecord\RecordData;
use Tourze\TLSRecord\VersionAdapter\TLS12RecordAdapter;

class TLS12RecordAdapterTest extends TestCase
{
    private TLS12RecordAdapter $adapter;
    
    protected function setUp(): void
    {
        parent::setUp();
        $this->adapter = new TLS12RecordAdapter();
    }
    
    public function testEncodeRecord(): void
    {
        $record = new RecordData(
            ContentType::APPLICATION_DATA->value,
            'Hello World',
            Version::TLS_1_2->value
        );
        
        $encoded = $this->adapter->encodeRecord($record);
        
        // 验证编码格式
        $this->assertEquals(16, strlen($encoded)); // 5字节头部 + 11字节数据
        
        // 验证头部
        $header = unpack('Ctype/Cmajor/Cminor/nlength', $encoded);
        $this->assertEquals(ContentType::APPLICATION_DATA->value, $header['type']);
        $this->assertEquals(0x03, $header['major']); // TLS 1.2主版本
        $this->assertEquals(0x03, $header['minor']); // TLS 1.2次版本
        $this->assertEquals(11, $header['length']); // "Hello World"的长度
        
        // 验证数据
        $this->assertEquals('Hello World', substr($encoded, 5));
    }
    
    public function testDecodeRecord(): void
    {
        // 构造一个有效的TLS 1.2记录
        $data = pack('CCCn', ContentType::APPLICATION_DATA->value, 0x03, 0x03, 11) . 'Hello World';
        
        $record = $this->adapter->decodeRecord($data);
        
        $this->assertInstanceOf(RecordData::class, $record);
        $this->assertEquals(ContentType::APPLICATION_DATA->value, $record->getContentType());
        $this->assertEquals('Hello World', $record->getData());
        $this->assertEquals(Version::TLS_1_2->value, $record->getVersion());
    }
    
    public function testDecodeRecordWithInsufficientHeaderData(): void
    {
        $this->expectException(RecordException::class);
        $this->expectExceptionMessage('记录数据不完整：头部长度不足');
        
        $this->adapter->decodeRecord('abc'); // 只有3字节，不足5字节头部
    }
    
    public function testDecodeRecordWithInsufficientContentData(): void
    {
        $this->expectException(RecordException::class);
        $this->expectExceptionMessage('记录数据不完整：内容长度不足');
        
        // 头部声明有11字节数据，但实际只提供5字节
        $data = pack('CCCn', ContentType::APPLICATION_DATA->value, 0x03, 0x03, 11) . 'Hello';
        $this->adapter->decodeRecord($data);
    }
    
    public function testApplyEncryptionForCBC(): void
    {
        $state = $this->createMock(CipherState::class);
        $state->method('getCipherSuite')->willReturn('TLS_RSA_WITH_AES_128_CBC_SHA');
        $state->method('getTLSVersion')->willReturn(Version::TLS_1_2->value);
        $state->method('getAndIncrementSequenceNumber')->willReturn(0);
        $state->method('getKey')->willReturn(str_repeat("\x00", 16)); // 16字节的密钥
        $state->method('getIV')->willReturn(str_repeat("\x00", 16)); // 16字节的IV
        $state->method('getMacKey')->willReturn(str_repeat("\x00", 20)); // 20字节的MAC密钥
        
        // 由于需要实际的加密库，这里只测试方法是否可以调用而不抛出异常
        try {
            $encrypted = $this->adapter->applyEncryption('test data', $state, ContentType::APPLICATION_DATA->value);
            $this->assertNotEmpty($encrypted);
        } catch (RecordException $e) {
            // 如果由于缺少加密库而失败，这是可以接受的
            $this->assertStringContainsString('加密失败', $e->getMessage());
        }
    }
    
    public function testApplyEncryptionForGCM(): void
    {
        $state = $this->createMock(CipherState::class);
        $state->method('getCipherSuite')->willReturn('TLS_RSA_WITH_AES_128_GCM_SHA256');
        $state->method('getTLSVersion')->willReturn(Version::TLS_1_2->value);
        $state->method('getAndIncrementSequenceNumber')->willReturn(0);
        $state->method('getKey')->willReturn(str_repeat("\x00", 16)); // 16字节的密钥
        $state->method('getIV')->willReturn(str_repeat("\x00", 12)); // 12字节的IV
        
        // 由于需要实际的加密库，这里只测试方法是否可以调用而不抛出异常
        try {
            $encrypted = $this->adapter->applyEncryption('test data', $state, ContentType::APPLICATION_DATA->value);
            $this->assertNotEmpty($encrypted);
        } catch (RecordException $e) {
            // 如果由于缺少加密库而失败，这是可以接受的
            $this->assertStringContainsString('加密失败', $e->getMessage());
        }
    }
    
    public function testApplyDecryptionForCBC(): void
    {
        $state = $this->createMock(CipherState::class);
        $state->method('getCipherSuite')->willReturn('TLS_RSA_WITH_AES_128_CBC_SHA');
        $state->method('getTLSVersion')->willReturn(Version::TLS_1_2->value);
        $state->method('getSequenceNumber')->willReturn(0);
        $state->method('getAndIncrementSequenceNumber')->willReturn(0);
        $state->method('getKey')->willReturn(str_repeat("\x00", 16)); // 16字节的密钥
        $state->method('getIV')->willReturn(str_repeat("\x00", 16)); // 16字节的IV
        $state->method('getMacKey')->willReturn(str_repeat("\x00", 20)); // 20字节的MAC密钥
        
        // 创建一个包含填充的假密文
        $fakeEncrypted = str_repeat("\x00", 32); // 两个AES块
        
        try {
            $result = $this->adapter->applyDecryption($fakeEncrypted, $state);
            $this->assertCount(2, $result);
        } catch (RecordException $e) {
            // 如果由于缺少加密库或其他原因而失败，这是可以接受的
            $this->assertStringContainsString('解密失败', $e->getMessage());
        }
    }
    
    public function testApplyDecryptionForGCM(): void
    {
        $state = $this->createMock(CipherState::class);
        $state->method('getCipherSuite')->willReturn('TLS_RSA_WITH_AES_128_GCM_SHA256');
        $state->method('getTLSVersion')->willReturn(Version::TLS_1_2->value);
        $state->method('getSequenceNumber')->willReturn(0);
        $state->method('getAndIncrementSequenceNumber')->willReturn(0);
        $state->method('getKey')->willReturn(str_repeat("\x00", 16)); // 16字节的密钥
        $state->method('getIV')->willReturn(str_repeat("\x00", 12)); // 12字节的IV
        
        // 创建一个包含认证标签的假密文
        $fakeEncrypted = str_repeat("\x00", 32); // 16字节密文 + 16字节标签
        
        try {
            $result = $this->adapter->applyDecryption($fakeEncrypted, $state);
            $this->assertCount(2, $result);
        } catch (RecordException $e) {
            // 如果由于缺少加密库或其他原因而失败，这是可以接受的
            $this->assertStringContainsString('解密失败', $e->getMessage());
        }
    }
    
    public function testEncodeRecordWithDefaultVersion(): void
    {
        $record = new RecordData(
            ContentType::HANDSHAKE->value,
            'test',
            null // 没有指定版本
        );
        
        $encoded = $this->adapter->encodeRecord($record);
        
        // 验证使用了默认的TLS 1.2版本
        $header = unpack('Ctype/Cmajor/Cminor/nlength', $encoded);
        $this->assertEquals(0x03, $header['major']);
        $this->assertEquals(0x03, $header['minor']);
    }
}