# TLS-Record

[English](README.md) | [中文](README.zh-CN.md)

TLS-Record package implements the Record Layer of the TLS protocol, which is one of the core components of TLS. The Record Layer is responsible for fragmenting data into manageable blocks, applying encryption and integrity protection to these blocks, and then encapsulating them into a consistent format for transmission.

## Installation

```bash
composer require tourze/tls-record
```

## Basic Usage

### Creating a Record Layer Instance

```php
use Tourze\TLSCommon\Version;
use Tourze\TLSRecord\RecordFactory;
use Tourze\TLSRecord\Transport\SocketTransport;

// Create transport layer
$transport = new SocketTransport('example.com', 443);

// Create record layer
$recordLayer = RecordFactory::create($transport, Version::TLS_1_2);
```

### Sending Records

```php
use Tourze\TLSCommon\Protocol\ContentType;

// Send handshake message
$recordLayer->sendRecord(ContentType::HANDSHAKE, $handshakeData);

// Send application data
$recordLayer->sendRecord(ContentType::APPLICATION_DATA, $applicationData);
```

### Receiving Records

```php
// Receive record
$record = $recordLayer->receiveRecord();

// Check record type
if ($record->getContentType() === ContentType::HANDSHAKE) {
    // Process handshake message
    $handshakeData = $record->getData();
} elseif ($record->getContentType() === ContentType::APPLICATION_DATA) {
    // Process application data
    $applicationData = $record->getData();
}
```

### Switching to Encrypted Mode

```php
use Tourze\TLSRecord\CipherState;

// Create cipher state
$cipherState = new CipherState(
    'TLS_AES_128_GCM_SHA256', // Cipher suite
    $key,                     // Encryption key
    $iv,                      // Initialization vector
    $macKey,                  // MAC key
    Version::TLS_1_2          // TLS version
);

// Switch to encrypted mode
$recordLayer->changeWriteCipherSpec($cipherState);
$recordLayer->changeReadCipherSpec($cipherState);
```

### Setting Maximum Fragment Length

```php
// Set maximum fragment length
$recordLayer->setMaxFragmentLength(8192);
```

## Custom Transport Layer

You can create custom transport layers by implementing the `Transport` interface:

```php
use Tourze\TLSRecord\Transport\Transport;

class CustomTransport implements Transport
{
    // Implement interface methods
    public function send(string $data): int
    {
        // Custom send implementation
    }
    
    public function receive(int $length): string
    {
        // Custom receive implementation
    }
    
    public function hasDataAvailable(int $timeout = 0): bool
    {
        // Custom check implementation
    }
    
    public function close(): void
    {
        // Custom close implementation
    }
}
```

## Supported TLS Versions

- TLS 1.0
- TLS 1.1
- TLS 1.2
- TLS 1.3

## Features

- Complete implementation of the TLS Record Layer protocol
- Support for record fragmentation and reassembly
- Support for encryption and MAC protection
- Support for differences between TLS 1.0 to TLS 1.3
- Efficient buffer management
- Defense against common TLS attacks
