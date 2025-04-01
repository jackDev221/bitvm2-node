# Libp2p 简单 NetworkBehaviour 示例

本示例展示如何创建一个基本的 NetworkBehaviour，包含简单的消息交换功能。

## 1. 定义消息类型

```rust
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub enum SimpleMessage {
    Hello(String),
    Echo(String),
    Error(String),
}
```

## 2. 实现网络行为

```rust
use libp2p::{
    request_response::{RequestResponse, RequestResponseEvent},
    NetworkBehaviour,
    PeerId,
};

// 自定义网络行为
#[derive(NetworkBehaviour)]
pub struct SimpleBehaviour {
    // 请求响应协议
    request_response: RequestResponse<SimpleCodec>,
}

// 自定义事件
#[derive(Debug)]
pub enum SimpleEvent {
    RequestResponse(RequestResponseEvent<SimpleMessage, SimpleMessage>),
}

// 实现 From trait
impl From<RequestResponseEvent<SimpleMessage, SimpleMessage>> for SimpleEvent {
    fn from(event: RequestResponseEvent<SimpleMessage, SimpleMessage>) -> Self {
        SimpleEvent::RequestResponse(event)
    }
}

// 实现编解码器
pub struct SimpleCodec;

impl RequestResponseCodec for SimpleCodec {
    type Protocol = StreamProtocol;
    type Request = SimpleMessage;
    type Response = SimpleMessage;

    fn read_request<T: AsyncRead>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
    ) -> Pin<Box<dyn Future<Output = Result<Self::Request, IoError>> + Send>> {
        Box::pin(async move {
            let mut buf = Vec::new();
            tokio::io::AsyncReadExt::read_to_end(io, &mut buf).await?;
            let request: SimpleMessage = serde_json::from_slice(&buf)
                .map_err(|e| IoError::new(ErrorKind::InvalidData, e))?;
            Ok(request)
        })
    }

    fn write_response<T: AsyncWrite>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        response: Self::Response,
    ) -> Pin<Box<dyn Future<Output = Result<(), IoError>> + Send>> {
        Box::pin(async move {
            let data = serde_json::to_vec(&response)
                .map_err(|e| IoError::new(ErrorKind::InvalidData, e))?;
            tokio::io::AsyncWriteExt::write_all(io, &data).await?;
            Ok(())
        })
    }
}
```

## 3. 实现行为方法

```rust
impl SimpleBehaviour {
    pub fn new() -> Self {
        // 初始化请求响应协议
        let request_response = RequestResponse::new(
            SimpleCodec,
            vec![(SimpleCodec, libp2p::core::Version::V1)],
            libp2p::request_response::Config::default(),
        );

        Self { request_response }
    }

    // 发送 Hello 消息
    pub fn send_hello(&mut self, peer: PeerId, message: String) -> OutboundRequestId {
        let request = SimpleMessage::Hello(message);
        self.request_response.send_request(&peer, request)
    }

    // 发送 Echo 消息
    pub fn send_echo(&mut self, peer: PeerId, message: String) -> OutboundRequestId {
        let request = SimpleMessage::Echo(message);
        self.request_response.send_request(&peer, request)
    }
}
```

## 4. 使用示例

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

    // 创建网络行为
    let mut behaviour = SimpleBehaviour::new();
    
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
                    SimpleEvent::RequestResponse(event) => {
                        match event {
                            RequestResponseEvent::Message {
                                peer,
                                message: RequestResponseMessage::Request { request, channel, .. },
                            } => {
                                match request {
                                    SimpleMessage::Hello(message) => {
                                        println!("收到来自 {} 的 Hello: {}", peer, message);
                                        // 发送响应
                                        swarm.behaviour_mut().request_response.send_response(
                                            &channel,
                                            SimpleMessage::Hello("你好!".to_string()),
                                        ).unwrap();
                                    }
                                    SimpleMessage::Echo(message) => {
                                        println!("收到来自 {} 的 Echo: {}", peer, message);
                                        // 回显消息
                                        swarm.behaviour_mut().request_response.send_response(
                                            &channel,
                                            SimpleMessage::Echo(message),
                                        ).unwrap();
                                    }
                                    SimpleMessage::Error(error) => {
                                        println!("收到错误: {}", error);
                                    }
                                }
                            }
                            RequestResponseEvent::Message {
                                peer,
                                message: RequestResponseMessage::Response { response, .. },
                            } => {
                                match response {
                                    SimpleMessage::Hello(message) => {
                                        println!("收到来自 {} 的 Hello 响应: {}", peer, message);
                                    }
                                    SimpleMessage::Echo(message) => {
                                        println!("收到来自 {} 的 Echo 响应: {}", peer, message);
                                    }
                                    SimpleMessage::Error(error) => {
                                        println!("收到错误响应: {}", error);
                                    }
                                }
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

## 5. 使用说明

1. **发送消息**
```rust
// 发送 Hello 消息
behaviour.send_hello(peer_id, "你好!".to_string());

// 发送 Echo 消息
behaviour.send_echo(peer_id, "测试消息".to_string());
```

2. **处理响应**
- 响应会在事件循环中通过 `RequestResponseMessage::Response` 事件接收
- 可以根据 `OutboundRequestId` 匹配请求和响应

3. **错误处理**
- 编解码器中的错误会被转换为 `IoError`
- 网络错误会在 Swarm 事件中处理

## 6. 注意事项

1. **协议设计**
   - 消息类型要简单明确
   - 考虑错误处理
   - 注意消息大小

2. **资源管理**
   - 及时清理不需要的连接
   - 控制并发请求数量
   - 处理超时情况

3. **调试**
   - 添加日志记录
   - 实现错误追踪
   - 监控网络状态

## 7. 扩展建议

1. **添加更多功能**
   - 心跳检测
   - 状态同步
   - 批量消息

2. **增强可靠性**
   - 重试机制
   - 超时处理
   - 错误恢复

3. **改进性能**
   - 消息压缩
   - 连接复用
   - 缓存机制 