<?php

namespace Tourze\TLSRecord\Tests\Security;

use PHPUnit\Framework\TestCase;
use Tourze\TLSCommon\Version;
use Tourze\TLSRecord\Security\PaddingOracleProtection;

class PaddingOracleProtectionTest extends TestCase
{
    public function testApplySplitRecordMitigation(): void
    {
        // 测试空字符串
        $result = PaddingOracleProtection::applySplitRecordMitigation('');
        $this->assertCount(1, $result);
        $this->assertEquals('', $result[0]);
        
        // 测试单字节字符串
        $result = PaddingOracleProtection::applySplitRecordMitigation('A');
        $this->assertCount(1, $result);
        $this->assertEquals('A', $result[0]);
        
        // 测试多字节字符串 - 应该被分割
        $result = PaddingOracleProtection::applySplitRecordMitigation('Hello World');
        $this->assertCount(2, $result);
        $this->assertEquals('H', $result[0]);
        $this->assertEquals('ello World', $result[1]);
    }
    
    public function testVerifyPaddingConstantTime(): void
    {
        $blockSize = 16;
        
        // 测试有效的PKCS#7填充
        $data = "Hello World" . str_repeat("\x05", 5); // 填充5个字节，每个值为5
        $result = PaddingOracleProtection::verifyPaddingConstantTime($data, $blockSize);
        $this->assertTrue($result[0]);
        $this->assertEquals(5, $result[1]); // 填充长度
        
        // 测试无效填充 - 填充值不一致
        $data = "Hello World" . "\x04\x03\x02\x01\x05"; // 最后一个字节是5，但前4个字节不是5
        $result = PaddingOracleProtection::verifyPaddingConstantTime($data, $blockSize);
        $this->assertFalse($result[0]);
        
        // 测试空数据
        $result = PaddingOracleProtection::verifyPaddingConstantTime('', $blockSize);
        $this->assertFalse($result[0]);
        $this->assertEquals(0, $result[1]);
        
        // 测试非块大小对齐的数据
        $data = "Hello"; // 5字节，不是16的倍数
        $result = PaddingOracleProtection::verifyPaddingConstantTime($data, $blockSize);
        $this->assertFalse($result[0]);
        
        // 测试填充值超过块大小
        $data = "Hello World" . str_repeat("\x20", 5); // 填充值32超过块大小16
        $result = PaddingOracleProtection::verifyPaddingConstantTime($data, $blockSize);
        $this->assertFalse($result[0]);
    }
    
    public function testSelectProtectionStrategy(): void
    {
        // TLS 1.3 应该返回 'none'
        $strategy = PaddingOracleProtection::selectProtectionStrategy(Version::TLS_1_3->value, 'TLS_AES_128_GCM_SHA256');
        $this->assertEquals('none', $strategy);
        
        // TLS 1.0 + CBC 应该返回 'split_records'
        $strategy = PaddingOracleProtection::selectProtectionStrategy(Version::TLS_1_0->value, 'TLS_RSA_WITH_AES_128_CBC_SHA');
        $this->assertEquals('split_records', $strategy);
        
        // TLS 1.1/1.2 + CBC 应该返回 'constant_time_padding'
        $strategy = PaddingOracleProtection::selectProtectionStrategy(Version::TLS_1_1->value, 'TLS_RSA_WITH_AES_128_CBC_SHA256');
        $this->assertEquals('constant_time_padding', $strategy);
        
        $strategy = PaddingOracleProtection::selectProtectionStrategy(Version::TLS_1_2->value, 'TLS_RSA_WITH_AES_256_CBC_SHA256');
        $this->assertEquals('constant_time_padding', $strategy);
        
        // AEAD 密码套件应该返回 'none'
        $strategy = PaddingOracleProtection::selectProtectionStrategy(Version::TLS_1_2->value, 'TLS_RSA_WITH_AES_128_GCM_SHA256');
        $this->assertEquals('none', $strategy);
        
        $strategy = PaddingOracleProtection::selectProtectionStrategy(Version::TLS_1_2->value, 'TLS_RSA_WITH_AES_128_CCM_8');
        $this->assertEquals('none', $strategy);
        
        $strategy = PaddingOracleProtection::selectProtectionStrategy(Version::TLS_1_2->value, 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256');
        $this->assertEquals('none', $strategy);
        
        // 未知密码套件应该返回 'constant_time_padding'
        $strategy = PaddingOracleProtection::selectProtectionStrategy(Version::TLS_1_2->value, 'UNKNOWN_CIPHER');
        $this->assertEquals('constant_time_padding', $strategy);
    }
    
    public function testApplyPKCS7Padding(): void
    {
        $blockSize = 16;
        
        // 测试需要填充1个字节的情况
        $plaintext = str_repeat('A', 15);
        $padded = PaddingOracleProtection::applyPKCS7Padding($plaintext, $blockSize);
        $this->assertEquals(16, strlen($padded));
        $this->assertEquals("\x01", $padded[15]);
        
        // 测试需要填充整个块的情况
        $plaintext = str_repeat('A', 16);
        $padded = PaddingOracleProtection::applyPKCS7Padding($plaintext, $blockSize);
        $this->assertEquals(32, strlen($padded));
        $this->assertEquals(str_repeat("\x10", 16), substr($padded, 16));
        
        // 测试空字符串
        $padded = PaddingOracleProtection::applyPKCS7Padding('', $blockSize);
        $this->assertEquals(16, strlen($padded));
        $this->assertEquals(str_repeat("\x10", 16), $padded);
    }
    
    public function testRemovePKCS7Padding(): void
    {
        $blockSize = 16;
        
        // 测试有效填充的移除
        $plaintext = "Hello World";
        $paddingLength = $blockSize - (strlen($plaintext) % $blockSize);
        $padded = $plaintext . str_repeat(chr($paddingLength), $paddingLength);
        
        $result = PaddingOracleProtection::removePKCS7Padding($padded, $blockSize);
        $this->assertEquals($plaintext, $result);
        
        // 测试无效填充 - 填充值为3，但前面的字节不正确
        $invalidPadded = "Hello World" . "\x05\x04\x03\x02\x03"; // 最后一个字节是3，表示有3个填充字节
        $result = PaddingOracleProtection::removePKCS7Padding($invalidPadded, $blockSize);
        $this->assertNull($result);
        
        // 测试整个块都是填充的情况
        $padded = str_repeat("\x10", 16);
        $result = PaddingOracleProtection::removePKCS7Padding($padded, $blockSize);
        $this->assertEquals('', $result);
    }
}