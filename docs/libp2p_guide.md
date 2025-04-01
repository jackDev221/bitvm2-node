# Libp2p 使用指南

## 简介

Libp2p 是一个模块化的网络协议栈，用于构建点对点网络应用。它提供了一系列网络协议和工具，使得开发者可以轻松构建去中心化应用。

## 核心概念

### 1. 传输层 (Transport)
- TCP
- WebSocket
- QUIC
- 自定义传输协议

### 2. 协议升级 (Protocol Upgrades)
- 加密 (Noise, TLS)
- 多路复用 (Yamux, Mplex)
- 身份验证

### 3. 网络行为 (Network Behaviour)
- Kademlia DHT
- mDNS
- Gossip
- 自定义协议

## 基本使用示例

### 1. 创建基础节点

```rust
use libp2p::{
    core::transport::Transport,
    noise,
    tcp,
    yamux,
    identity,
    PeerId,
};

#[tokio::main]
async fn main() {
    // 生成密钥对
    let id_keys = identity::Keypair::generate_ed25519();
    let peer_id = PeerId::from(id_keys.public());

    // 创建传输层
    let transport = tcp::tokio::Transport::new(tcp::Config::default())
        .expect("创建 TCP 传输层失败")
        .upgrade(libp2p::core::upgrade::Version::V1)
        .authenticate(noise::Config::new(&id_keys).expect("创建 Noise 配置失败"))
        .multiplex(yamux::Config::default())
        .boxed();

    println!("节点 ID: {}", peer_id);
}
```

### 2. 添加 Kademlia DHT

```rust
use libp2p::{
    kad::{store::MemoryStore, Behaviour as Kademlia},
    swarm::SwarmEvent,
};

#[derive(NetworkBehaviour)]
struct MyBehaviour {
    kademlia: Kademlia<MemoryStore>,
}

impl MyBehaviour {
    fn new(peer_id: PeerId) -> Self {
        let store = MemoryStore::new(peer_id);
        let kademlia = Kademlia::new(peer_id, store);
        
        Self { kademlia }
    }
}
```

### 3. 启动 Swarm

```rust
use libp2p::swarm::{Swarm, SwarmEvent};

let mut swarm = Swarm::new(transport, behaviour, peer_id);

// 监听地址
let addr = "/ip4/0.0.0.0/tcp/0".parse().unwrap();
swarm.listen_on(addr).unwrap();

// 事件循环
while let Some(event) = swarm.next().await {
    match event {
        SwarmEvent::NewListenAddr { address, .. } => {
            println!("监听地址: {}", address);
        }
        SwarmEvent::Behaviour(event) => {
            // 处理网络行为事件
        }
        _ => {}
    }
}
```

## 高级功能

### 1. 自定义协议

```rust
use libp2p::{
    request_response::{RequestResponse, RequestResponseEvent},
    swarm::SwarmEvent,
};

#[derive(NetworkBehaviour)]
struct CustomBehaviour {
    request_response: RequestResponse<CustomCodec>,
}

#[derive(Debug)]
enum CustomCodec {
    // 自定义协议消息类型
}

impl RequestResponseCodec for CustomCodec {
    type Protocol = StreamProtocol;
    type Request = String;
    type Response = String;

    fn read_request<T: AsyncRead>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
    ) -> Pin<Box<dyn Future<Output = Result<Self::Request, IoError>> + Send>> {
        // 实现请求读取逻辑
    }

    fn write_response<T: AsyncWrite>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        response: Self::Response,
    ) -> Pin<Box<dyn Future<Output = Result<(), IoError>> + Send>> {
        // 实现响应写入逻辑
    }
}
```

### 2. 节点发现

```rust
// 添加引导节点
let bootstrap_addr = "/ip4/1.2.3.4/tcp/63785/p2p/QmBootstrap...".parse().unwrap();
swarm.dial(bootstrap_addr).unwrap();

// 使用 mDNS 进行本地节点发现
#[derive(NetworkBehaviour)]
struct DiscoveryBehaviour {
    kademlia: Kademlia<MemoryStore>,
    mdns: mdns::tokio::Behaviour,
}
```

## 最佳实践

1. **错误处理**
   - 使用 Result 类型处理可能的错误
   - 实现适当的重试机制
   - 记录关键错误信息

2. **资源管理**
   - 合理设置超时时间
   - 及时清理不需要的连接
   - 监控内存使用

3. **安全性**
   - 使用加密传输
   - 实现身份验证
   - 验证对等节点

4. **性能优化**
   - 使用连接池
   - 实现请求限流
   - 优化数据序列化

## 常见问题

1. **连接问题**
   - 检查防火墙设置
   - 验证地址格式
   - 确认节点可达性

2. **协议兼容性**
   - 确保协议版本匹配
   - 验证编解码器实现
   - 处理协议升级

3. **内存管理**
   - 监控 DHT 存储大小
   - 清理过期数据
   - 实现资源限制

## 调试技巧

1. 使用日志记录关键事件
2. 实现健康检查机制
3. 添加性能指标收集
4. 使用网络分析工具

## 参考资源

- [Libp2p 官方文档](https://docs.libp2p.io/)
- [Rust Libp2p 文档](https://docs.rs/libp2p)
- [IPFS 文档](https://docs.ipfs.tech/) 