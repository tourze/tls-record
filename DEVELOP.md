# TLS-Record 包开发文档

## 1. 概述

TLS-Record 包负责实现 TLS 协议的记录层（Record Layer），是 TLS 协议的核心组件之一。记录层负责将要发送的数据分片成可管理的块，并对这些块应用加密和完整性保护，然后将其封装成一致的格式进行传输。

## 2. 主要职责

- ✅ 实现 TLS 记录层协议
- ✅ 处理数据的分片和重组
- ✅ 应用加密和压缩
- ✅ 管理序列号和 MAC（消息认证码）
- ✅ 处理记录头和正文的封装与解析
- ✅ 实现记录格式化和解析
- ✅ 支持记录层状态转换
- ✅ 实现不同 TLS 版本的记录层处理差异
- ✅ 处理最大片段长度限制
- ✅ 提供记录层的缓冲管理

## 3. 依赖关系

- ✅ **tls-common**：使用基础数据结构、常量定义和工具函数
- 🔄 **tls-crypto**：利用其提供的加密、解密和完整性保护功能（已实现基础集成，需进一步完善）

## 4. 核心组件设计

### 4.1 记录层结构

✅ TLS 记录层的基本结构如下：

```
 struct {
     ContentType type;                 // 1 字节，内容类型
     ProtocolVersion version;          // 2 字节，协议版本
     uint16 length;                    // 2 字节，片段长度
     opaque fragment[TLSPlaintext.length];  // 实际数据
 } TLSPlaintext;
```

### 4.2 内容类型

✅ 记录层支持以下内容类型：

- `change_cipher_spec (20)`：密码规格变更
- `alert (21)`：警告消息
- `handshake (22)`：握手消息
- `application_data (23)`：应用数据
- `heartbeat (24)`：心跳消息（TLS 1.2及以上）

### 4.3 状态机

✅ 记录层包含两个状态：

1. **未加密状态**：初始状态，握手过程中使用
2. **加密状态**：握手完成后使用，应用加密和MAC保护

## 5. 类设计

### 5.1 核心类

✅ 已完成以下核心类的实现：

#### RecordProtocol

```php
interface RecordProtocol
{
    /**
     * 发送TLS记录
     */
    public function sendRecord(int $contentType, string $data): void;
    
    /**
     * 接收TLS记录
     */
    public function receiveRecord(): RecordData;
    
    /**
     * 切换到加密状态
     */
    public function changeWriteCipherSpec(CipherState $state): void;
    
    /**
     * 切换到加密状态（读取方向）
     */
    public function changeReadCipherSpec(CipherState $state): void;
    
    /**
     * 设置最大片段长度
     */
    public function setMaxFragmentLength(int $length): void;
}
```

#### RecordData

✅ 已实现记录数据容器类：

```php
class RecordData
{
    private int $contentType;
    private string $data;
    private ?int $version;
    
    // 构造函数、getter 方法等
}
```

#### RecordLayer

✅ 已实现记录层主实现类：

```php
class RecordLayer implements RecordProtocol
{
    private Transport $transport;
    private ?CipherState $readState;
    private ?CipherState $writeState;
    private int $tlsVersion;
    private int $maxFragmentLength;
    private RecordVersionAdapter $versionAdapter;
    private string $receiveBuffer;
    
    // 实现 RecordProtocol 接口的方法
}
```

#### CipherState

✅ 已实现加密状态管理类：

```php
class CipherState
{
    private string $cipherSuite;
    private string $key;
    private string $iv;
    private string $macKey;
    private int $sequenceNumber;
    private int $tlsVersion;
    
    // 加密和MAC相关方法
}
```

### 5.2 版本适配器

✅ 已实现版本适配器接口和实现类：

```php
interface RecordVersionAdapter
{
    public function encodeRecord(RecordData $record): string;
    public function decodeRecord(string $data): RecordData;
    public function applyEncryption(string $plaintext, CipherState $state, int $contentType): string;
    public function applyDecryption(string $ciphertext, CipherState $state): array;
}

class TLS12RecordAdapter implements RecordVersionAdapter
{
    // TLS 1.2 特定实现
}

class TLS13RecordAdapter implements RecordVersionAdapter
{
    // TLS 1.3 特定实现
}
```

## 6. 实现要点

### 6.1 片段处理

✅ 已完成：
- 实现将大数据块分割成符合最大片段长度的多个记录
- 处理接收端的记录重组
- 支持最大片段长度扩展

### 6.2 加密处理

✅ 已完成基础框架：
- TLS 1.2 及以下：实现 MAC-then-Encrypt 处理流程
- TLS 1.3：实现 AEAD 加密方式
- 管理记录序列号，确保唯一性和顺序性

🔄 需要进一步完善：
- 与 tls-crypto 包的深度集成
- 更复杂加密场景的支持

### 6.3 版本兼容性

✅ 已完成：
- 适配不同 TLS 版本的记录格式差异
- 支持 TLS 1.0 的 CBC 填充预言攻击防护
- 实现 TLS 1.3 的 record 类型加密

### 6.4 记录缓冲区管理

✅ 已完成：
- 设计高效的缓冲区管理，减少内存复制操作
- 处理不完整记录和分段记录

### 6.5 错误处理

✅ 已完成：
- 检测并处理记录格式错误
- 识别MAC验证失败和解密失败
- 生成适当的警告消息

## 7. 安全考量

### 7.1 防御措施

✅ 已完成：
- 实现常量时间MAC比较，防止时序攻击
- 对所有填充操作使用常量时间验证

🔄 进行中：
- 防御 BEAST、POODLE 等填充预言攻击
- 实现 TLS 1.3 的记录层保护机制

### 7.2 性能优化

⏳ 计划中：
- 使用批量处理减少函数调用开销
- 优化内存使用，减少不必要的数据复制
- 实现可配置的缓冲区大小

## 8. 测试计划

### 8.1 单元测试

✅ 已完成基础测试：
- 测试记录层编码和解码
- 测试最大片段长度设置
- 测试基本的发送和接收功能

🔄 进行中：
- 测试加密和解密操作
- 测试MAC生成和验证
- 测试序列号管理

### 8.2 集成测试

⏳ 计划中：
- 与tls-crypto包的集成测试
- 不同TLS版本的兼容性测试
- 边界条件测试（最大片段长度、大数据传输等）

### 8.3 安全测试

⏳ 计划中：
- 填充预言攻击模拟测试
- 时序攻击尝试
- 异常输入测试

## 9. 接口示例

✅ 已实现的基本使用方式：

```php
// 创建记录层实例
$transport = new SocketTransport('example.com', 443);
$recordLayer = RecordFactory::create($transport, TLSVersion::TLS_1_2);

// 发送握手消息
$recordLayer->sendRecord(ContentType::HANDSHAKE, $handshakeData);

// 接收记录
$record = $recordLayer->receiveRecord();
if ($record->getContentType() === ContentType::HANDSHAKE) {
    // 处理握手消息
}

// 切换到加密模式
$recordLayer->changeWriteCipherSpec($cipherState);
$recordLayer->changeReadCipherSpec($cipherState);

// 发送应用数据
$recordLayer->sendRecord(ContentType::APPLICATION_DATA, $applicationData);
```

## 10. 开发路线图

✅ 已完成：
- 实现基本记录层结构和状态管理
- 添加TLS 1.2记录处理支持
- 实现基础加密和MAC功能框架
- 添加TLS 1.3记录支持
- 完善基础错误处理

🔄 进行中：
- 完善与tls-crypto包的集成
  - 实现AEAD加密模式的完整支持
  - 优化密钥交换和管理机制
  - 增强与不同密码套件的兼容性
- 完善安全防御措施
  - 加强针对BEAST、POODLE等填充预言攻击的防御
  - 完善TLS 1.3的记录层保护机制
  - 实现针对重放攻击的额外防护
- 增强错误处理和异常恢复机制
  - 完善记录层解析错误的详细诊断信息
  - 增加对异常加密状态的恢复能力
  - 实现更细粒度的错误日志记录

⏳ 计划中：
- 进行性能优化
  - 实现批量记录处理以减少函数调用开销
  - 优化缓冲区管理以减少内存分配和复制
  - 引入可配置的性能参数（如缓冲区大小）
- 全面测试和安全审查
  - 完善单元测试覆盖所有边界情况
  - 实现与其他TLS组件的端到端集成测试
  - 进行第三方安全审计
- 扩展更多高级功能
  - 支持0-RTT数据传输（TLS 1.3）
  - 实现记录层压缩功能（考虑安全性）
  - 添加更多调试和监控接口
- 支持更多加密套件
  - 完善对ChaCha20-Poly1305的支持
  - 增加对未来密码套件的扩展机制
  - 优化密码套件选择算法

## 11. 已知问题与解决方案

### 11.1 当前限制

- 记录片段大小优化不足，可能导致网络利用率不佳
- 对某些旧版TLS实现的兼容性支持有限
- 内存使用在处理大量并发连接时需要优化

### 11.2 解决计划

- 实现智能分片算法，根据网络状况动态调整记录大小
- 添加兼容性模式，支持与旧版TLS服务器的通信
- 引入内存池和对象复用机制，降低GC压力
