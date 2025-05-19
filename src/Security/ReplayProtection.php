<?php

namespace Tourze\TLSRecord\Security;

/**
 * TLS记录层的重放攻击防御类
 * 
 * 重放攻击是指攻击者捕获并重新发送有效的数据传输，使接收方重复处理已经处理过的记录。
 * 该类通过维护滑动窗口和记录已处理的序列号，防止记录被重放。
 */
class ReplayProtection
{
    /**
     * 滑动窗口大小（记录个数）
     */
    private const DEFAULT_WINDOW_SIZE = 64;
    
    /**
     * 最高已接收序列号
     */
    private int $highestSeq = -1;
    
    /**
     * 滑动窗口位图（记录窗口内已接收的记录）
     */
    private array $windowBitmap = [];
    
    /**
     * 窗口大小
     */
    private int $windowSize;
    
    /**
     * 构造函数
     *
     * @param int $windowSize 滑动窗口大小（可选）
     */
    public function __construct(int $windowSize = self::DEFAULT_WINDOW_SIZE)
    {
        $this->windowSize = $windowSize;
        $this->resetBitmap();
    }
    
    /**
     * 重置位图
     */
    private function resetBitmap(): void
    {
        $this->windowBitmap = array_fill(0, $this->windowSize, false);
    }
    
    /**
     * 检查序列号是否已被处理（是否是重放）
     *
     * @param int $seqNum 序列号
     * @return bool 如果是重放返回true，否则返回false
     */
    public function isReplay(int $seqNum): bool
    {
        // 如果序列号大于等于最高序列号+窗口大小，则肯定不是重放（新记录超出窗口）
        if ($seqNum >= $this->highestSeq + $this->windowSize) {
            return false;
        }
        
        // 如果序列号小于等于最高序列号-窗口大小，则肯定是重放（太旧的记录）
        if ($this->highestSeq > $this->windowSize && $seqNum <= $this->highestSeq - $this->windowSize) {
            return true;
        }
        
        // 如果是首次出现的序列号
        if ($this->highestSeq < 0) {
            return false;
        }
        
        // 如果序列号大于最高序列号，肯定不是重放
        if ($seqNum > $this->highestSeq) {
            return false;
        }
        
        // 此时序列号在窗口内，检查位图
        $offset = $this->highestSeq - $seqNum;
        if ($offset < $this->windowSize) {
            return $this->windowBitmap[$offset];
        }
        
        // 如果到达这里，则可能是实现错误或者窗口大小过小
        return true;
    }
    
    /**
     * 标记序列号为已处理
     *
     * @param int $seqNum 序列号
     */
    public function markAsProcessed(int $seqNum): void
    {
        // 首次接收的记录
        if ($this->highestSeq < 0) {
            $this->highestSeq = $seqNum;
            $this->windowBitmap[0] = true;
            return;
        }
        
        // 如果序列号高于当前最高序列号
        if ($seqNum > $this->highestSeq) {
            // 计算需要移动的位数
            $shift = $seqNum - $this->highestSeq;
            
            // 如果移动量大于等于窗口大小，重置整个位图
            if ($shift >= $this->windowSize) {
                $this->resetBitmap();
            } else {
                // 移动位图
                for ($i = $this->windowSize - 1; $i >= $shift; $i--) {
                    $this->windowBitmap[$i] = $this->windowBitmap[$i - $shift];
                }
                
                // 新位置之前的位置置为false
                for ($i = 0; $i < $shift; $i++) {
                    $this->windowBitmap[$i] = false;
                }
            }
            
            // 设置新序列号位置为已处理
            $this->windowBitmap[0] = true;
            $this->highestSeq = $seqNum;
        } else if ($seqNum <= $this->highestSeq) {
            // 序列号在当前窗口内
            $offset = $this->highestSeq - $seqNum;
            if ($offset < $this->windowSize) {
                $this->windowBitmap[$offset] = true;
            }
        }
    }
    
    /**
     * 获取最高已处理序列号
     *
     * @return int 最高序列号
     */
    public function getHighestSequence(): int
    {
        return $this->highestSeq;
    }
    
    /**
     * 检查并标记序列号（原子操作）
     *
     * @param int $seqNum 序列号
     * @return bool 如果是重放返回true，否则返回false
     */
    public function checkAndMark(int $seqNum): bool
    {
        $isReplay = $this->isReplay($seqNum);
        
        if (!$isReplay) {
            $this->markAsProcessed($seqNum);
        }
        
        return $isReplay;
    }
    
    /**
     * 重置保护状态
     */
    public function reset(): void
    {
        $this->highestSeq = -1;
        $this->resetBitmap();
    }
}
