<?php

declare(strict_types=1);

namespace Tourze\TLSRecord\Tests\Unit\Exception;

use PHPUnit\Framework\TestCase;
use Tourze\TLSRecord\Exception\RecordException;

/**
 * RecordException 单元测试
 */
class RecordExceptionTest extends TestCase
{
    /**
     * 测试异常可以被实例化
     */
    public function testCanBeInstantiated(): void
    {
        $exception = new RecordException('Test message');
        $this->assertInstanceOf(RecordException::class, $exception);
        $this->assertInstanceOf(\Exception::class, $exception);
    }

    /**
     * 测试异常消息
     */
    public function testExceptionMessage(): void
    {
        $message = 'TLS record error occurred';
        $exception = new RecordException($message);
        $this->assertEquals($message, $exception->getMessage());
    }

    /**
     * 测试异常代码
     */
    public function testExceptionCode(): void
    {
        $code = 500;
        $exception = new RecordException('Error', $code);
        $this->assertEquals($code, $exception->getCode());
    }

    /**
     * 测试异常链
     */
    public function testExceptionChaining(): void
    {
        $previous = new \RuntimeException('Previous error');
        $exception = new RecordException('Current error', 0, $previous);
        $this->assertSame($previous, $exception->getPrevious());
    }

    /**
     * 测试异常可以被抛出和捕获
     */
    public function testExceptionCanBeThrown(): void
    {
        $this->expectException(RecordException::class);
        $this->expectExceptionMessage('Record processing failed');
        
        throw new RecordException('Record processing failed');
    }

    /**
     * 测试异常继承关系
     */
    public function testExceptionInheritance(): void
    {
        $exception = new RecordException('Test');
        
        // 可以作为 Exception 被捕获
        $caught = false;
        try {
            throw $exception;
        } catch (\Exception $e) {
            $caught = true;
            $this->assertSame($exception, $e);
        }
        
        $this->assertTrue($caught, 'Exception should be caught as \Exception');
    }
}