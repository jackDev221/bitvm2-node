# Libp2p 自定义协议示例

本示例展示如何实现一个简单的聊天协议，允许节点之间发送和接收消息。

## 1. 定义协议消息

首先，我们需要定义协议中使用的消息类型：

```rust
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub enum ChatMessage {
    Text(String),
    Ping,
    Pong,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ChatRequest {
    pub message: ChatMessage,
    pub timestamp: u64,
}
```

## 2. 实现协议编解码器

```rust
use libp2p::{
    core::upgrade::ProtocolName,
    request_response::{RequestResponseCodec, OutboundRequestId},
    StreamProtocol,
};
use std::io::{Error as IoError, ErrorKind};
use tokio::io::{AsyncRead, AsyncWrite};
use std::pin::Pin;
use std::future::Future;

pub struct ChatCodec;

impl ProtocolName for ChatCodec {
    fn protocol_name(&self) -> &[u8] {
        "/chat/1.0.0".as_bytes()
    }
}

impl RequestResponseCodec for ChatCodec {
    type Protocol = StreamProtocol;
    type Request = ChatRequest;
    type Response = ChatMessage;

    fn read_request<T: AsyncRead>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
    ) -> Pin<Box<dyn Future<Output = Result<Self::Request, IoError>> + Send>> {
        Box::pin(async move {
            let mut buf = Vec::new();
            tokio::io::AsyncReadExt::read_to_end(io, &mut buf).await?;
            
            let request: ChatRequest = serde_json::from_slice(&buf)
                .map_err(|e| IoError::new(ErrorKind::InvalidData, e))?;
            
            Ok(request)
        })
    }

    fn write_request<T: AsyncWrite>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        request: Self::Request,
    ) -> Pin<Box<dyn Future<Output = Result<(), IoError>> + Send>> {
        Box::pin(async move {
            let data = serde_json::to_vec(&request)
                .map_err(|e| IoError::new(ErrorKind::InvalidData, e))?;
            
            tokio::io::AsyncWriteExt::write_all(io, &data).await?;
            Ok(())
        })
    }

    fn read_response<T: AsyncRead>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
    ) -> Pin<Box<dyn Future<Output = Result<Self::Response, IoError>> + Send>> {
        Box::pin(async move {
            let mut buf = Vec::new();
            tokio::io::AsyncReadExt::read_to_end(io, &mut buf).await?;
            
            let response: ChatMessage = serde_json::from_slice(&buf)
                .map_err(|e| IoError::new(ErrorKind::InvalidData, e))?;
            
            Ok(response)
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

## 3. 实现网络行为

```rust
use libp2p::{
    NetworkBehaviour,
    request_response::{RequestResponse, RequestResponseEvent},
    swarm::SwarmEvent,
};

#[derive(NetworkBehaviour)]
pub struct ChatBehaviour {
    request_response: RequestResponse<ChatCodec>,
}

impl ChatBehaviour {
    pub fn new() -> Self {
        let request_response = RequestResponse::new(
            ChatCodec,
            vec![(ChatCodec, libp2p::core::Version::V1)],
            libp2p::request_response::Config::default(),
        );

        Self { request_response }
    }

    pub fn send_message(&mut self, peer: PeerId, message: ChatMessage) -> OutboundRequestId {
        let request = ChatRequest {
            message,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };
        
        self.request_response.send_request(&peer, request)
    }
}
```

## 4. 使用示例

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
    // 创建传输层
    let transport = tcp::tokio::Transport::new(tcp::Config::default())
        .expect("创建 TCP 传输层失败")
        .upgrade(libp2p::core::upgrade::Version::V1)
        .authenticate(noise::Config::new(&id_keys).expect("创建 Noise 配置失败"))
        .multiplex(yamux::Config::default())
        .boxed();

    // 创建网络行为
    let mut behaviour = ChatBehaviour::new();
    
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
            SwarmEvent::Behaviour(RequestResponseEvent::Message {
                peer,
                message: RequestResponseMessage::Request { request, channel, .. },
            }) => {
                // 处理接收到的请求
                match request.message {
                    ChatMessage::Text(text) => {
                        println!("收到来自 {} 的消息: {}", peer, text);
                        // 发送响应
                        swarm.behaviour_mut().request_response.send_response(
                            &channel,
                            ChatMessage::Text("收到消息".to_string()),
                        ).unwrap();
                    }
                    ChatMessage::Ping => {
                        println!("收到来自 {} 的 Ping", peer);
                        swarm.behaviour_mut().request_response.send_response(
                            &channel,
                            ChatMessage::Pong,
                        ).unwrap();
                    }
                    _ => {}
                }
            }
            SwarmEvent::Behaviour(RequestResponseEvent::Message {
                peer,
                message: RequestResponseMessage::Response { response, .. },
            }) => {
                // 处理接收到的响应
                match response {
                    ChatMessage::Text(text) => {
                        println!("收到来自 {} 的响应: {}", peer, text);
                    }
                    ChatMessage::Pong => {
                        println!("收到来自 {} 的 Pong", peer);
                    }
                    _ => {}
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
// 发送文本消息
behaviour.send_message(peer_id, ChatMessage::Text("Hello!".to_string()));

// 发送 Ping
behaviour.send_message(peer_id, ChatMessage::Ping);
```

2. **处理响应**
- 响应会在事件循环中通过 `RequestResponseMessage::Response` 事件接收
- 可以根据 `OutboundRequestId` 匹配请求和响应

3. **错误处理**
- 编解码器中的错误会被转换为 `IoError`
- 网络错误会在 Swarm 事件中处理

## 6. 注意事项

1. **协议版本**
   - 确保所有节点使用相同的协议版本
   - 在协议名称中包含版本号（如 "/chat/1.0.0"）

2. **消息大小**
   - 考虑消息大小限制
   - 实现分片机制处理大消息

3. **超时处理**
   - 设置请求超时
   - 实现重试机制

4. **并发控制**
   - 限制并发请求数量
   - 实现请求队列

## 7. 扩展建议

1. **添加更多消息类型**
   - 文件传输
   - 状态同步
   - 命令执行

2. **实现可靠传输**
   - 消息确认
   - 重传机制
   - 序列号

3. **添加安全特性**
   - 消息签名
   - 加密传输
   - 访问控制 