# Libp2p NetworkBehaviour 自定义示例

本示例展示如何创建一个自定义的 NetworkBehaviour，包含多个网络协议行为。

## 1. 定义自定义行为

首先，我们创建一个包含多个网络协议的自定义行为：

```rust
use libp2p::{
    kad::{store::MemoryStore, Behaviour as Kademlia},
    mdns,
    ping,
    request_response::{RequestResponse, RequestResponseEvent},
    swarm::SwarmEvent,
    NetworkBehaviour,
    PeerId,
};

// 自定义消息类型
#[derive(Debug, Serialize, Deserialize)]
pub enum CustomMessage {
    Text(String),
    Data(Vec<u8>),
}

// 自定义编解码器
pub struct CustomCodec;

impl RequestResponseCodec for CustomCodec {
    type Protocol = StreamProtocol;
    type Request = CustomMessage;
    type Response = CustomMessage;
    // ... 实现编解码方法
}

// 自定义网络行为
#[derive(NetworkBehaviour)]
pub struct CustomBehaviour {
    // Kademlia DHT
    kademlia: Kademlia<MemoryStore>,
    
    // mDNS 本地发现
    mdns: mdns::tokio::Behaviour,
    
    // Ping 协议
    ping: ping::Behaviour,
    
    // 自定义请求响应协议
    custom_protocol: RequestResponse<CustomCodec>,
}

// 自定义事件类型
#[derive(Debug)]
pub enum CustomEvent {
    Kademlia(kad::Event),
    Mdns(mdns::Event),
    Ping(ping::Event),
    Custom(RequestResponseEvent<CustomMessage, CustomMessage>),
}

// 为自定义行为实现 From trait
impl From<kad::Event> for CustomEvent {
    fn from(event: kad::Event) -> Self {
        CustomEvent::Kademlia(event)
    }
}

impl From<mdns::Event> for CustomEvent {
    fn from(event: mdns::Event) -> Self {
        CustomEvent::Mdns(event)
    }
}

impl From<ping::Event> for CustomEvent {
    fn from(event: ping::Event) -> Self {
        CustomEvent::Ping(event)
    }
}

impl From<RequestResponseEvent<CustomMessage, CustomMessage>> for CustomEvent {
    fn from(event: RequestResponseEvent<CustomMessage, CustomMessage>) -> Self {
        CustomEvent::Custom(event)
    }
}
```

## 2. 实现自定义行为

```rust
impl CustomBehaviour {
    pub fn new(peer_id: PeerId) -> Self {
        // 初始化 Kademlia
        let store = MemoryStore::new(peer_id);
        let kademlia = Kademlia::new(peer_id, store);

        // 初始化 mDNS
        let mdns = mdns::tokio::Behaviour::new(
            mdns::Config::default(),
            peer_id,
        ).expect("创建 mDNS 行为失败");

        // 初始化 Ping
        let ping = ping::Behaviour::default();

        // 初始化自定义协议
        let custom_protocol = RequestResponse::new(
            CustomCodec,
            vec![(CustomCodec, libp2p::core::Version::V1)],
            libp2p::request_response::Config::default(),
        );

        Self {
            kademlia,
            mdns,
            ping,
            custom_protocol,
        }
    }

    // 添加 Kademlia 引导节点
    pub fn add_bootstrap_node(&mut self, peer_id: PeerId, addr: Multiaddr) {
        self.kademlia.add_address(&peer_id, addr.clone());
        self.kademlia.bootstrap().unwrap();
    }

    // 发送自定义消息
    pub fn send_custom_message(&mut self, peer: PeerId, message: CustomMessage) -> OutboundRequestId {
        self.custom_protocol.send_request(&peer, message)
    }
}
```

## 3. 使用示例

```rust
#[tokio::main]
async fn main() {
    // 创建传输层
    let transport = tcp::tokio::Transport::new(tcp::Config::default())
        .expect("创建 TCP 传输层失败")
        .upgrade(libp2p::core::upgrade::Version::V1)
        .authenticate(noise::Config::new(&id_keys).expect("创建 Noise 配置失败"))
        .multiplex(yamux::Config::default())
        .boxed();

    // 创建自定义行为
    let mut behaviour = CustomBehaviour::new(peer_id);

    // 添加引导节点
    let bootstrap_addr = "/ip4/1.2.3.4/tcp/63785/p2p/QmBootstrap...".parse().unwrap();
    behaviour.add_bootstrap_node(bootstrap_peer_id, bootstrap_addr);

    // 创建 Swarm
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
                match event {
                    CustomEvent::Kademlia(event) => {
                        match event {
                            kad::Event::OutboundQueryCompleted { result, .. } => {
                                match result {
                                    Ok(kad::QueryResult::Bootstrap(ok)) => {
                                        println!("Kademlia 引导完成: {:?}", ok);
                                    }
                                    Ok(kad::QueryResult::GetProviders(ok)) => {
                                        println!("获取提供者完成: {:?}", ok);
                                    }
                                    _ => {}
                                }
                            }
                            _ => {}
                        }
                    }
                    CustomEvent::Mdns(event) => {
                        match event {
                            mdns::Event::Discovered(list) => {
                                for (peer_id, addr) in list {
                                    println!("发现新节点: {} at {}", peer_id, addr);
                                    swarm.dial(addr).unwrap();
                                }
                            }
                            mdns::Event::Expired(list) => {
                                for (peer_id, addr) in list {
                                    println!("节点离线: {} at {}", peer_id, addr);
                                }
                            }
                        }
                    }
                    CustomEvent::Ping(event) => {
                        match event {
                            ping::Event { peer, result, .. } => {
                                match result {
                                    Ok(ping::Success::Ping { rtt }) => {
                                        println!("Ping {}: {}ms", peer, rtt.as_millis());
                                    }
                                    Ok(ping::Success::Pong) => {
                                        println!("收到来自 {} 的 Pong", peer);
                                    }
                                    Err(e) => {
                                        println!("Ping {} 失败: {:?}", peer, e);
                                    }
                                }
                            }
                        }
                    }
                    CustomEvent::Custom(event) => {
                        match event {
                            RequestResponseEvent::Message {
                                peer,
                                message: RequestResponseMessage::Request { request, channel, .. },
                            } => {
                                println!("收到来自 {} 的消息: {:?}", peer, request);
                                // 发送响应
                                swarm.behaviour_mut().custom_protocol.send_response(
                                    &channel,
                                    CustomMessage::Text("收到消息".to_string()),
                                ).unwrap();
                            }
                            RequestResponseEvent::Message {
                                peer,
                                message: RequestResponseMessage::Response { response, .. },
                            } => {
                                println!("收到来自 {} 的响应: {:?}", peer, response);
                            }
                            _ => {}
                        }
                    }
                }
            }
            _ => {}
        }
    }
}
```

## 4. 使用说明

1. **添加新的协议行为**
   - 在 `CustomBehaviour` 结构体中添加新的字段
   - 实现相应的 `From` trait
   - 在事件处理中添加对应的处理逻辑

2. **协议交互**
   - Kademlia: 用于 DHT 和节点发现
   - mDNS: 用于本地网络发现
   - Ping: 用于节点存活检测
   - 自定义协议: 用于特定业务逻辑

3. **事件处理**
   - 使用 `match` 语句处理不同类型的事件
   - 根据事件类型执行相应的操作
   - 处理错误和异常情况

## 5. 注意事项

1. **协议配置**
   - 合理设置协议参数
   - 处理协议版本兼容性
   - 实现协议升级机制

2. **资源管理**
   - 控制并发连接数
   - 管理内存使用
   - 处理超时情况

3. **错误处理**
   - 实现优雅的错误处理
   - 添加重试机制
   - 记录错误日志

4. **性能优化**
   - 使用连接池
   - 实现缓存机制
   - 优化消息处理

## 6. 扩展建议

1. **添加更多协议**
   - Gossip 协议
   - PubSub 协议
   - 自定义协议

2. **增强功能**
   - 节点认证
   - 消息加密
   - 流量控制

3. **监控和调试**
   - 添加指标收集
   - 实现日志记录
   - 提供调试接口 