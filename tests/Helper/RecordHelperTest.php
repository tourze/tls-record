<?php

namespace Tourze\TLSRecord\Tests\Helper;

use PHPUnit\Framework\TestCase;
use Tourze\TLSCommon\Protocol\ContentType;
use Tourze\TLSCommon\Version;

class RecordHelperTest extends TestCase
{
    public function testBuildRecord(): void
    {
        $contentType = ContentType::APPLICATION_DATA->value;
        $version = Version::TLS_1_2->value;
        $data = 'Hello World';
        
        $record = RecordHelper::buildRecord($contentType, $version, $data);
        
        // 验证记录长度
        $this->assertEquals(16, strlen($record)); // 5字节头部 + 11字节数据
        
        // 解析并验证头部
        $header = unpack('Ctype/Cmajor/Cminor/nlength', $record);
        $this->assertEquals($contentType, $header['type']);
        $this->assertEquals(0x03, $header['major']); // TLS 1.2主版本
        $this->assertEquals(0x03, $header['minor']); // TLS 1.2次版本
        $this->assertEquals(11, $header['length']); // "Hello World"的长度
        
        // 验证数据部分
        $this->assertEquals($data, substr($record, 5));
    }
    
    public function testBuildMultipleRecords(): void
    {
        $records = [
            [ContentType::HANDSHAKE->value, Version::TLS_1_2->value, 'First'],
            [ContentType::APPLICATION_DATA->value, Version::TLS_1_2->value, 'Second'],
            [ContentType::ALERT->value, Version::TLS_1_2->value, 'Third'],
        ];
        
        $combined = RecordHelper::buildMultipleRecords($records);
        
        // 验证总长度
        $expectedLength = (5 + 5) + (5 + 6) + (5 + 5); // 每个记录的头部+数据长度
        $this->assertEquals($expectedLength, strlen($combined));
        
        // 验证第一个记录
        $offset = 0;
        $header1 = unpack('Ctype/Cmajor/Cminor/nlength', substr($combined, $offset, 5));
        $this->assertEquals(ContentType::HANDSHAKE->value, $header1['type']);
        $this->assertEquals(5, $header1['length']);
        $this->assertEquals('First', substr($combined, $offset + 5, 5));
        
        // 验证第二个记录
        $offset += 10;
        $header2 = unpack('Ctype/Cmajor/Cminor/nlength', substr($combined, $offset, 5));
        $this->assertEquals(ContentType::APPLICATION_DATA->value, $header2['type']);
        $this->assertEquals(6, $header2['length']);
        $this->assertEquals('Second', substr($combined, $offset + 5, 6));
        
        // 验证第三个记录
        $offset += 11;
        $header3 = unpack('Ctype/Cmajor/Cminor/nlength', substr($combined, $offset, 5));
        $this->assertEquals(ContentType::ALERT->value, $header3['type']);
        $this->assertEquals(5, $header3['length']);
        $this->assertEquals('Third', substr($combined, $offset + 5, 5));
    }
    
    public function testBuildHandshakeRecord(): void
    {
        $version = Version::TLS_1_2->value;
        $data = 'Handshake Data';
        
        $record = RecordHelper::buildHandshakeRecord($version, $data);
        
        // 解析并验证头部
        $header = unpack('Ctype/Cmajor/Cminor/nlength', $record);
        $this->assertEquals(ContentType::HANDSHAKE->value, $header['type']);
        $this->assertEquals(0x03, $header['major']);
        $this->assertEquals(0x03, $header['minor']);
        $this->assertEquals(strlen($data), $header['length']);
        
        // 验证数据
        $this->assertEquals($data, substr($record, 5));
    }
    
    public function testBuildApplicationDataRecord(): void
    {
        $version = Version::TLS_1_3->value;
        $data = 'Application Data';
        
        $record = RecordHelper::buildApplicationDataRecord($version, $data);
        
        // 解析并验证头部
        $header = unpack('Ctype/Cmajor/Cminor/nlength', $record);
        $this->assertEquals(ContentType::APPLICATION_DATA->value, $header['type']);
        $this->assertEquals(0x03, $header['major']); // TLS 1.3主版本
        $this->assertEquals(0x04, $header['minor']); // TLS 1.3次版本
        $this->assertEquals(strlen($data), $header['length']);
        
        // 验证数据
        $this->assertEquals($data, substr($record, 5));
    }
    
    public function testBuildAlertRecord(): void
    {
        $version = Version::TLS_1_2->value;
        $data = "\x02\x28"; // fatal, handshake_failure
        
        $record = RecordHelper::buildAlertRecord($version, $data);
        
        // 解析并验证头部
        $header = unpack('Ctype/Cmajor/Cminor/nlength', $record);
        $this->assertEquals(ContentType::ALERT->value, $header['type']);
        $this->assertEquals(0x03, $header['major']);
        $this->assertEquals(0x03, $header['minor']);
        $this->assertEquals(2, $header['length']);
        
        // 验证数据
        $this->assertEquals($data, substr($record, 5));
    }
    
    public function testBuildRecordWithEmptyData(): void
    {
        $record = RecordHelper::buildRecord(
            ContentType::APPLICATION_DATA->value,
            Version::TLS_1_2->value,
            ''
        );
        
        // 验证记录长度（只有头部）
        $this->assertEquals(5, strlen($record));
        
        // 解析并验证头部
        $header = unpack('Ctype/Cmajor/Cminor/nlength', $record);
        $this->assertEquals(0, $header['length']);
    }
    
    public function testBuildRecordWithLargeData(): void
    {
        $largeData = str_repeat('A', 16384); // 16KB的数据
        
        $record = RecordHelper::buildRecord(
            ContentType::APPLICATION_DATA->value,
            Version::TLS_1_2->value,
            $largeData
        );
        
        // 验证记录长度
        $this->assertEquals(5 + 16384, strlen($record));
        
        // 解析并验证头部
        $header = unpack('Ctype/Cmajor/Cminor/nlength', $record);
        $this->assertEquals(16384, $header['length']);
        
        // 验证数据
        $this->assertEquals($largeData, substr($record, 5));
    }
}