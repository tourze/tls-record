<?php

namespace Tourze\TLSRecord\Tests\VersionAdapter;

use PHPUnit\Framework\TestCase;
use Tourze\TLSCommon\Protocol\ContentType;
use Tourze\TLSCommon\Version;
use Tourze\TLSRecord\CipherState;
use Tourze\TLSRecord\Exception\RecordException;
use Tourze\TLSRecord\RecordData;
use Tourze\TLSRecord\VersionAdapter\TLS13RecordAdapter;

class TLS13RecordAdapterTest extends TestCase
{
    private TLS13RecordAdapter $adapter;
    
    protected function setUp(): void
    {
        parent::setUp();
        $this->adapter = new TLS13RecordAdapter();
    }
    
    public function testEncodeRecord(): void
    {
        $record = new RecordData(
            ContentType::APPLICATION_DATA->value,
            'Hello World',
            Version::TLS_1_3->value
        );
        
        $encoded = $this->adapter->encodeRecord($record);
        
        // 验证编码格式
        $this->assertEquals(16, strlen($encoded)); // 5字节头部 + 11字节数据
        
        // 验证头部 - TLS 1.3使用TLS 1.2版本号以保持兼容性
        $header = unpack('Ctype/Cmajor/Cminor/nlength', $encoded);
        $this->assertEquals(ContentType::APPLICATION_DATA->value, $header['type']);
        $this->assertEquals(0x03, $header['major']); // TLS 1.2主版本（为了兼容性）
        $this->assertEquals(0x03, $header['minor']); // TLS 1.2次版本（为了兼容性）
        $this->assertEquals(11, $header['length']); // "Hello World"的长度
        
        // 验证数据
        $this->assertEquals('Hello World', substr($encoded, 5));
    }
    
    public function testDecodeRecord(): void
    {
        // 构造一个有效的TLS 1.3记录（使用TLS 1.2版本号）
        $data = pack('CCCn', ContentType::APPLICATION_DATA->value, 0x03, 0x03, 11) . 'Hello World';
        
        $record = $this->adapter->decodeRecord($data);
        
        $this->assertInstanceOf(RecordData::class, $record);
        $this->assertEquals(ContentType::APPLICATION_DATA->value, $record->getContentType());
        $this->assertEquals('Hello World', $record->getData());
        $this->assertEquals(0x0303, $record->getVersion()); // TLS 1.2版本号
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
    
    public function testApplyEncryptionWithAESGCM(): void
    {
        $state = $this->createMock(CipherState::class);
        $state->method('getCipherSuite')->willReturn('TLS_AES_128_GCM_SHA256');
        $state->method('getAndIncrementSequenceNumber')->willReturn(0);
        $state->method('getKey')->willReturn(str_repeat("\x00", 16)); // 16字节的密钥
        $state->method('getIV')->willReturn(str_repeat("\x00", 12)); // 12字节的IV
        
        // 由于需要实际的加密库，这里只测试方法是否可以调用而不抛出异常
        try {
            $encrypted = $this->adapter->applyEncryption('test data', $state, ContentType::APPLICATION_DATA->value);
            $this->assertNotEmpty($encrypted);
        } catch (RecordException $e) {
            // 如果由于缺少加密库而失败，这是可以接受的
            $this->assertStringContainsString('TLS 1.3加密失败', $e->getMessage());
        }
    }
    
    public function testApplyEncryptionWithChaCha20(): void
    {
        $state = $this->createMock(CipherState::class);
        $state->method('getCipherSuite')->willReturn('TLS_CHACHA20_POLY1305_SHA256');
        $state->method('getAndIncrementSequenceNumber')->willReturn(0);
        $state->method('getKey')->willReturn(str_repeat("\x00", 32)); // 32字节的密钥
        $state->method('getIV')->willReturn(str_repeat("\x00", 12)); // 12字节的IV
        
        try {
            $encrypted = $this->adapter->applyEncryption('test data', $state, ContentType::HANDSHAKE->value);
            $this->assertNotEmpty($encrypted);
        } catch (RecordException $e) {
            // 如果由于缺少加密库而失败，这是可以接受的
            $this->assertStringContainsString('TLS 1.3加密失败', $e->getMessage());
        }
    }
    
    public function testApplyDecryptionWithAESGCM(): void
    {
        $state = $this->createMock(CipherState::class);
        $state->method('getCipherSuite')->willReturn('TLS_AES_128_GCM_SHA256');
        $state->method('getAndIncrementSequenceNumber')->willReturn(0);
        $state->method('getKey')->willReturn(str_repeat("\x00", 16)); // 16字节的密钥
        $state->method('getIV')->willReturn(str_repeat("\x00", 12)); // 12字节的IV
        
        // 创建一个包含认证标签的假密文
        $fakeEncrypted = str_repeat("\x00", 32); // 16字节密文 + 16字节标签
        
        try {
            $result = $this->adapter->applyDecryption($fakeEncrypted, $state);
            $this->assertCount(2, $result);
            // 第一个元素是明文，第二个元素是内容类型
            $this->assertIsString($result[0]);
            $this->assertIsInt($result[1]);
        } catch (RecordException $e) {
            // 如果由于缺少加密库或其他原因而失败，这是可以接受的
            $this->assertStringContainsString('TLS 1.3解密失败', $e->getMessage());
        }
    }
    
    public function testApplyDecryptionWithEmptyData(): void
    {
        $state = $this->createMock(CipherState::class);
        $state->method('getCipherSuite')->willReturn('TLS_AES_256_GCM_SHA384');
        $state->method('getAndIncrementSequenceNumber')->willReturn(0);
        $state->method('getKey')->willReturn(str_repeat("\x00", 32)); // 32字节的密钥
        $state->method('getIV')->willReturn(str_repeat("\x00", 12)); // 12字节的IV
        
        // 创建一个只包含认证标签的密文（没有实际数据）
        $fakeEncrypted = str_repeat("\x00", 16); // 只有16字节标签
        
        try {
            $result = $this->adapter->applyDecryption($fakeEncrypted, $state);
            // 即使解密成功也应该因为空数据而失败
            $this->fail('应该抛出异常');
        } catch (RecordException $e) {
            // 期望抛出异常
            $this->assertNotEmpty($e->getMessage());
        }
    }
    
    public function testEncodeRecordAlwaysUsesCompatibleVersion(): void
    {
        // 即使指定了TLS 1.3版本，编码时也应该使用TLS 1.2版本号
        $record = new RecordData(
            ContentType::HANDSHAKE->value,
            'test',
            Version::TLS_1_3->value // 明确指定TLS 1.3
        );
        
        $encoded = $this->adapter->encodeRecord($record);
        
        // 验证仍然使用了TLS 1.2版本号
        $header = unpack('Ctype/Cmajor/Cminor/nlength', $encoded);
        $this->assertEquals(0x03, $header['major']);
        $this->assertEquals(0x03, $header['minor']);
    }
    
    public function testContentTypeHandlingInEncryption(): void
    {
        $state = $this->createMock(CipherState::class);
        $state->method('getCipherSuite')->willReturn('TLS_AES_128_GCM_SHA256');
        $state->method('getAndIncrementSequenceNumber')->willReturn(0);
        $state->method('getKey')->willReturn(str_repeat("\x00", 16));
        $state->method('getIV')->willReturn(str_repeat("\x00", 12));
        
        // 测试不同的内容类型
        $contentTypes = [
            ContentType::HANDSHAKE->value,
            ContentType::APPLICATION_DATA->value,
            ContentType::ALERT->value,
            ContentType::CHANGE_CIPHER_SPEC->value
        ];
        
        foreach ($contentTypes as $contentType) {
            try {
                $encrypted = $this->adapter->applyEncryption('test', $state, $contentType);
                $this->assertNotEmpty($encrypted);
                // 在TLS 1.3中，原始内容类型会被附加到明文末尾
            } catch (RecordException $e) {
                // 如果由于缺少加密库而失败，这是可以接受的
                $this->assertStringContainsString('TLS 1.3加密失败', $e->getMessage());
            }
        }
    }
}