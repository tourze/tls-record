<?php

namespace Tourze\TLSRecord\Tests\Security;

use PHPUnit\Framework\TestCase;
use Tourze\TLSRecord\Security\ReplayProtection;

class ReplayProtectionTest extends TestCase
{
    private ReplayProtection $replayProtection;
    
    protected function setUp(): void
    {
        parent::setUp();
        $this->replayProtection = new ReplayProtection();
    }
    
    public function testIsReplayForFirstSequence(): void
    {
        // 第一个序列号不应该是重放
        $this->assertFalse($this->replayProtection->isReplay(0));
        $this->assertFalse($this->replayProtection->isReplay(100));
    }
    
    public function testMarkAsProcessedAndIsReplay(): void
    {
        // 标记序列号5为已处理
        $this->replayProtection->markAsProcessed(5);
        
        // 序列号5现在应该被检测为重放
        $this->assertTrue($this->replayProtection->isReplay(5));
        
        // 序列号6不应该是重放
        $this->assertFalse($this->replayProtection->isReplay(6));
        
        // 标记序列号6
        $this->replayProtection->markAsProcessed(6);
        
        // 序列号6现在应该被检测为重放
        $this->assertTrue($this->replayProtection->isReplay(6));
        
        // 序列号4不应该是重放（在窗口内但未处理）
        $this->assertFalse($this->replayProtection->isReplay(4));
    }
    
    public function testWindowSliding(): void
    {
        $windowSize = 64; // 默认窗口大小
        
        // 标记序列号0
        $this->replayProtection->markAsProcessed(0);
        
        // 标记序列号100（远超窗口）
        $this->replayProtection->markAsProcessed(100);
        
        // 序列号0现在应该被检测为重放（太旧）
        $this->assertTrue($this->replayProtection->isReplay(0));
        
        // 序列号37应该不是重放（在窗口内）
        $this->assertFalse($this->replayProtection->isReplay(37));
        
        // 序列号36应该被检测为重放（刚好超出窗口）
        $this->assertTrue($this->replayProtection->isReplay(36));
    }
    
    public function testGetHighestSequence(): void
    {
        // 初始时应该是-1
        $this->assertEquals(-1, $this->replayProtection->getHighestSequence());
        
        // 标记序列号10
        $this->replayProtection->markAsProcessed(10);
        $this->assertEquals(10, $this->replayProtection->getHighestSequence());
        
        // 标记序列号5（低于当前最高）
        $this->replayProtection->markAsProcessed(5);
        $this->assertEquals(10, $this->replayProtection->getHighestSequence());
        
        // 标记序列号20（高于当前最高）
        $this->replayProtection->markAsProcessed(20);
        $this->assertEquals(20, $this->replayProtection->getHighestSequence());
    }
    
    public function testCheckAndMark(): void
    {
        // 第一次检查序列号10，应该不是重放
        $this->assertFalse($this->replayProtection->checkAndMark(10));
        
        // 再次检查序列号10，应该是重放
        $this->assertTrue($this->replayProtection->checkAndMark(10));
        
        // 检查新序列号11，应该不是重放
        $this->assertFalse($this->replayProtection->checkAndMark(11));
    }
    
    public function testReset(): void
    {
        // 标记一些序列号
        $this->replayProtection->markAsProcessed(5);
        $this->replayProtection->markAsProcessed(10);
        $this->replayProtection->markAsProcessed(15);
        
        // 验证它们被检测为重放
        $this->assertTrue($this->replayProtection->isReplay(5));
        $this->assertTrue($this->replayProtection->isReplay(10));
        $this->assertEquals(15, $this->replayProtection->getHighestSequence());
        
        // 重置
        $this->replayProtection->reset();
        
        // 所有序列号现在都不应该是重放
        $this->assertFalse($this->replayProtection->isReplay(5));
        $this->assertFalse($this->replayProtection->isReplay(10));
        $this->assertFalse($this->replayProtection->isReplay(15));
        $this->assertEquals(-1, $this->replayProtection->getHighestSequence());
    }
    
    public function testCustomWindowSize(): void
    {
        // 创建一个窗口大小为10的实例
        $smallWindowProtection = new ReplayProtection(10);
        
        // 标记序列号0
        $smallWindowProtection->markAsProcessed(0);
        
        // 标记序列号15（超过窗口大小）
        $smallWindowProtection->markAsProcessed(15);
        
        // 序列号0应该被检测为重放（太旧）
        $this->assertTrue($smallWindowProtection->isReplay(0));
        
        // 序列号5应该被检测为重放（超出小窗口）
        $this->assertTrue($smallWindowProtection->isReplay(4));
        
        // 序列号6应该不是重放（在窗口内）
        $this->assertFalse($smallWindowProtection->isReplay(6));
    }
    
    public function testSequentialProcessing(): void
    {
        // 模拟按顺序处理序列号
        for ($i = 0; $i < 100; $i++) {
            $this->assertFalse($this->replayProtection->isReplay($i));
            $this->replayProtection->markAsProcessed($i);
        }
        
        // 验证所有处理过的序列号都被检测为重放
        for ($i = 36; $i < 100; $i++) { // 从36开始，因为0-35超出窗口
            $this->assertTrue($this->replayProtection->isReplay($i));
        }
        
        // 验证太旧的序列号被检测为重放
        for ($i = 0; $i < 36; $i++) {
            $this->assertTrue($this->replayProtection->isReplay($i));
        }
    }
    
    public function testOutOfOrderProcessing(): void
    {
        // 处理乱序的序列号
        $sequences = [10, 5, 15, 3, 20, 8, 12];
        
        foreach ($sequences as $seq) {
            $this->assertFalse($this->replayProtection->isReplay($seq));
            $this->replayProtection->markAsProcessed($seq);
        }
        
        // 验证所有处理过的序列号都被检测为重放
        foreach ($sequences as $seq) {
            $this->assertTrue($this->replayProtection->isReplay($seq));
        }
        
        // 验证未处理的序列号不被检测为重放
        $this->assertFalse($this->replayProtection->isReplay(7));
        $this->assertFalse($this->replayProtection->isReplay(11));
        $this->assertFalse($this->replayProtection->isReplay(19));
    }
}