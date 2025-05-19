<?php

namespace Tourze\TLSRecord;

/**
 * TLS记录数据类，用于存储记录内容类型和实际数据
 */
class RecordData
{
    /**
     * @param int $contentType 内容类型（参见ContentType类）
     * @param string $data 记录数据
     * @param int|null $version TLS协议版本（可选）
     */
    public function __construct(
        private readonly int $contentType,
        private readonly string $data,
        private readonly ?int $version = null
    ) {
    }
    
    /**
     * 获取记录内容类型
     */
    public function getContentType(): int
    {
        return $this->contentType;
    }
    
    /**
     * 获取记录数据
     */
    public function getData(): string
    {
        return $this->data;
    }
    
    /**
     * 获取TLS协议版本
     */
    public function getVersion(): ?int
    {
        return $this->version;
    }
}
