# TLS-Record

TLS-Record 包负责实现 TLS 协议的记录层（Record Layer），是 TLS 协议的核心组件之一。记录层负责将要发送的数据分片成可管理的块，并对这些块应用加密和完整性保护，然后将其封装成一致的格式进行传输。

## 安装

```bash
composer require tourze/tls-record
```

## 基本用法

### 创建记录层实例

```php
use Tourze\TLSCommon\Version;
use Tourze\TLSRecord\RecordFactory;
use Tourze\TLSRecord\Transport\SocketTransport;

// 创建传输层
$transport = new SocketTransport('example.com', 443);

// 创建记录层
$recordLayer = RecordFactory::create($transport, Version::TLS_1_2);
```

### 发送记录

```php
use Tourze\TLSCommon\Protocol\ContentType;

// 发送握手消息
$recordLayer->sendRecord(ContentType::HANDSHAKE, $handshakeData);

// 发送应用数据
$recordLayer->sendRecord(ContentType::APPLICATION_DATA, $applicationData);
```

### 接收记录

```php
// 接收记录
$record = $recordLayer->receiveRecord();

// 检查记录类型
if ($record->getContentType() === ContentType::HANDSHAKE) {
    // 处理握手消息
    $handshakeData = $record->getData();
} elseif ($record->getContentType() === ContentType::APPLICATION_DATA) {
    // 处理应用数据
    $applicationData = $record->getData();
}
```

### 切换到加密模式

```php
use Tourze\TLSRecord\CipherState;

// 创建加密状态
$cipherState = new CipherState(
    'TLS_AES_128_GCM_SHA256', // 加密套件
    $key,                     // 加密密钥
    $iv,                      // 初始化向量
    $macKey,                  // MAC密钥
    Version::TLS_1_2          // TLS版本
);

// 切换到加密模式
$recordLayer->changeWriteCipherSpec($cipherState);
$recordLayer->changeReadCipherSpec($cipherState);
```

### 设置最大片段长度

```php
// 设置最大片段长度
$recordLayer->setMaxFragmentLength(8192);
```

## 自定义传输层

可以通过实现 `Transport` 接口来创建自定义的传输层：

```php
use Tourze\TLSRecord\Transport\Transport;

class CustomTransport implements Transport
{
    // 实现接口方法
    public function send(string $data): int
    {
        // 自定义发送实现
    }
    
    public function receive(int $length): string
    {
        // 自定义接收实现
    }
    
    public function hasDataAvailable(int $timeout = 0): bool
    {
        // 自定义检查实现
    }
    
    public function close(): void
    {
        // 自定义关闭实现
    }
}
```

## 支持的TLS版本

- TLS 1.0
- TLS 1.1
- TLS 1.2
- TLS 1.3

## 特性

- 完整实现TLS记录层协议
- 支持记录分片和重组
- 支持加密和MAC保护
- 支持TLS 1.0至TLS 1.3的版本差异
- 提供高效的缓冲区管理
- 防御常见的TLS攻击 