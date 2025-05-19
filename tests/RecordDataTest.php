<?php

namespace Tourze\TLSRecord\Tests;

use PHPUnit\Framework\TestCase;
use Tourze\TLSCommon\Protocol\ContentType;
use Tourze\TLSCommon\Version;
use Tourze\TLSRecord\RecordData;

/**
 * RecordData类单元测试
 */
class RecordDataTest extends TestCase
{
    /**
     * 测试基本属性设置和获取
     */
    public function testBasicProperties(): void
    {
        // 测试数据
        $contentType = ContentType::HANDSHAKE->value;
        $data = 'test data';
        $version = Version::TLS_1_2->value;
        
        // 创建记录数据对象
        $record = new RecordData($contentType, $data, $version);
        
        // 验证属性
        $this->assertEquals($contentType, $record->getContentType());
        $this->assertEquals($data, $record->getData());
        $this->assertEquals($version, $record->getVersion());
    }
    
    /**
     * 测试不同内容类型
     */
    public function testDifferentContentTypes(): void
    {
        // 测试握手内容类型
        $record1 = new RecordData(ContentType::HANDSHAKE->value, 'handshake data');
        $this->assertEquals(ContentType::HANDSHAKE->value, $record1->getContentType());
        
        // 测试应用数据内容类型
        $record2 = new RecordData(ContentType::APPLICATION_DATA->value, 'app data');
        $this->assertEquals(ContentType::APPLICATION_DATA->value, $record2->getContentType());
        
        // 测试警告内容类型
        $record3 = new RecordData(ContentType::ALERT->value, 'alert data');
        $this->assertEquals(ContentType::ALERT->value, $record3->getContentType());
        
        // 测试密码规格变更内容类型
        $record4 = new RecordData(ContentType::CHANGE_CIPHER_SPEC->value, 'change cipher spec');
        $this->assertEquals(ContentType::CHANGE_CIPHER_SPEC->value, $record4->getContentType());
    }
    
    /**
     * 测试不同数据长度
     */
    public function testDifferentDataLengths(): void
    {
        // 测试空数据
        $record1 = new RecordData(ContentType::APPLICATION_DATA->value, '');
        $this->assertEquals('', $record1->getData());
        $this->assertEquals(0, strlen($record1->getData()));
        
        // 测试短数据
        $record2 = new RecordData(ContentType::APPLICATION_DATA->value, 'short');
        $this->assertEquals('short', $record2->getData());
        $this->assertEquals(5, strlen($record2->getData()));
        
        // 测试长数据
        $longData = str_repeat('a', 16384); // 16KB数据
        $record3 = new RecordData(ContentType::APPLICATION_DATA->value, $longData);
        $this->assertEquals($longData, $record3->getData());
        $this->assertEquals(16384, strlen($record3->getData()));
    }
    
    /**
     * 测试可选版本参数
     */
    public function testOptionalVersionParameter(): void
    {
        // 不指定版本
        $record1 = new RecordData(ContentType::HANDSHAKE->value, 'data');
        $this->assertNull($record1->getVersion());
        
        // 指定TLS 1.0版本
        $record2 = new RecordData(ContentType::HANDSHAKE->value, 'data', Version::TLS_1_0->value);
        $this->assertEquals(Version::TLS_1_0->value, $record2->getVersion());
        
        // 指定TLS 1.1版本
        $record3 = new RecordData(ContentType::HANDSHAKE->value, 'data', Version::TLS_1_1->value);
        $this->assertEquals(Version::TLS_1_1->value, $record3->getVersion());
        
        // 指定TLS 1.2版本
        $record4 = new RecordData(ContentType::HANDSHAKE->value, 'data', Version::TLS_1_2->value);
        $this->assertEquals(Version::TLS_1_2->value, $record4->getVersion());
        
        // 指定TLS 1.3版本
        $record5 = new RecordData(ContentType::HANDSHAKE->value, 'data', Version::TLS_1_3->value);
        $this->assertEquals(Version::TLS_1_3->value, $record5->getVersion());
    }
    
    /**
     * 测试二进制数据
     */
    public function testBinaryData(): void
    {
        // 创建一些二进制数据
        $binaryData = pack('Cnnn', 0x01, 0x02, 0x03, 0x04);
        
        // 创建记录
        $record = new RecordData(ContentType::APPLICATION_DATA->value, $binaryData);
        
        // 验证数据未被修改
        $this->assertEquals($binaryData, $record->getData());
        $this->assertEquals(7, strlen($record->getData())); // 二进制长度应为7字节
    }
} 