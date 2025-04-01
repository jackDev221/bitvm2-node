# Libp2p 文件共享网络示例

本示例展示如何创建一个基于 libp2p 的文件共享网络，包含文件发现、传输和验证功能。

## 1. 定义消息类型

```rust
use serde::{Deserialize, Serialize};
use std::time::SystemTime;

#[derive(Debug, Serialize, Deserialize)]
pub enum FileMessage {
    // 文件元数据
    FileInfo {
        hash: String,
        size: u64,
        name: String,
        timestamp: u64,
    },
    // 文件请求
    FileRequest {
        hash: String,
        offset: u64,
        length: u64,
    },
    // 文件数据块
    FileChunk {
        hash: String,
        offset: u64,
        data: Vec<u8>,
    },
    // 错误响应
    Error(String),
}

// 文件元数据
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileMetadata {
    pub hash: String,
    pub size: u64,
    pub name: String,
    pub timestamp: u64,
    pub owner: PeerId,
}
```

## 2. 实现网络行为

```rust
use libp2p::{
    kad::{store::MemoryStore, Behaviour as Kademlia},
    request_response::{RequestResponse, RequestResponseEvent},
    NetworkBehaviour,
    PeerId,
};

#[derive(NetworkBehaviour)]
pub struct FileShareBehaviour {
    // Kademlia DHT 用于文件发现
    kademlia: Kademlia<MemoryStore>,
    
    // 文件传输协议
    file_protocol: RequestResponse<FileCodec>,
}

// 自定义事件
#[derive(Debug)]
pub enum FileShareEvent {
    Kademlia(kad::Event),
    File(RequestResponseEvent<FileMessage, FileMessage>),
}

// 实现 From trait
impl From<kad::Event> for FileShareEvent {
    fn from(event: kad::Event) -> Self {
        FileShareEvent::Kademlia(event)
    }
}

impl From<RequestResponseEvent<FileMessage, FileMessage>> for FileShareEvent {
    fn from(event: RequestResponseEvent<FileMessage, FileMessage>) -> Self {
        FileShareEvent::File(event)
    }
}

// 实现编解码器
pub struct FileCodec;

impl RequestResponseCodec for FileCodec {
    type Protocol = StreamProtocol;
    type Request = FileMessage;
    type Response = FileMessage;

    fn read_request<T: AsyncRead>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
    ) -> Pin<Box<dyn Future<Output = Result<Self::Request, IoError>> + Send>> {
        Box::pin(async move {
            let mut buf = Vec::new();
            tokio::io::AsyncReadExt::read_to_end(io, &mut buf).await?;
            let request: FileMessage = serde_json::from_slice(&buf)
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

## 3. 实现文件共享行为

```rust
impl FileShareBehaviour {
    pub fn new(peer_id: PeerId) -> Self {
        // 初始化 Kademlia
        let store = MemoryStore::new(peer_id);
        let kademlia = Kademlia::new(peer_id, store);

        // 初始化文件协议
        let file_protocol = RequestResponse::new(
            FileCodec,
            vec![(FileCodec, libp2p::core::Version::V1)],
            libp2p::request_response::Config::default(),
        );

        Self {
            kademlia,
            file_protocol,
        }
    }

    // 发布文件信息
    pub fn publish_file(&mut self, metadata: FileMetadata) {
        let key = format!("/file/{}", metadata.hash);
        let value = serde_json::to_vec(&metadata).unwrap();
        self.kademlia.put_record(
            kad::record::Key::new(&key),
            kad::record::Record {
                key: kad::record::Key::new(&key),
                value,
                publisher: None,
                expires: None,
            },
            kad::Quorum::One,
        );
    }

    // 查找文件
    pub fn find_file(&mut self, hash: &str) {
        let key = format!("/file/{}", hash);
        self.kademlia.get_record(
            &kad::record::Key::new(&key),
            kad::Quorum::One,
        );
    }

    // 请求文件块
    pub fn request_file_chunk(
        &mut self,
        peer: PeerId,
        hash: String,
        offset: u64,
        length: u64,
    ) -> OutboundRequestId {
        let request = FileMessage::FileRequest {
            hash,
            offset,
            length,
        };
        self.file_protocol.send_request(&peer, request)
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

    // 创建文件共享行为
    let mut behaviour = FileShareBehaviour::new(peer_id);

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
            SwarmEvent::Behaviour(event) => {
                match event {
                    FileShareEvent::Kademlia(event) => {
                        match event {
                            kad::Event::OutboundQueryCompleted { result, .. } => {
                                match result {
                                    Ok(kad::QueryResult::GetProviders(ok)) => {
                                        println!("找到文件提供者: {:?}", ok);
                                        // 开始从提供者下载文件
                                        for provider in ok.providers {
                                            swarm.behaviour_mut().request_file_chunk(
                                                provider,
                                                "file_hash".to_string(),
                                                0,
                                                1024,
                                            );
                                        }
                                    }
                                    Ok(kad::QueryResult::GetRecord(ok)) => {
                                        if let Some(record) = ok.records.first() {
                                            let metadata: FileMetadata = serde_json::from_slice(&record.value).unwrap();
                                            println!("获取到文件信息: {:?}", metadata);
                                        }
                                    }
                                    _ => {}
                                }
                            }
                            _ => {}
                        }
                    }
                    FileShareEvent::File(event) => {
                        match event {
                            RequestResponseEvent::Message {
                                peer,
                                message: RequestResponseMessage::Request { request, channel, .. },
                            } => {
                                match request {
                                    FileMessage::FileRequest { hash, offset, length } => {
                                        // 处理文件请求
                                        let chunk = read_file_chunk(hash, offset, length).await;
                                        swarm.behaviour_mut().file_protocol.send_response(
                                            &channel,
                                            FileMessage::FileChunk {
                                                hash: hash.clone(),
                                                offset,
                                                data: chunk,
                                            },
                                        ).unwrap();
                                    }
                                    _ => {}
                                }
                            }
                            RequestResponseEvent::Message {
                                peer,
                                message: RequestResponseMessage::Response { response, .. },
                            } => {
                                match response {
                                    FileMessage::FileChunk { hash, offset, data } => {
                                        // 处理接收到的文件块
                                        save_file_chunk(hash, offset, &data).await;
                                    }
                                    FileMessage::Error(error) => {
                                        println!("文件传输错误: {}", error);
                                    }
                                    _ => {}
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

1. **文件发布**
   - 计算文件哈希
   - 创建文件元数据
   - 通过 Kademlia 发布文件信息

2. **文件发现**
   - 使用文件哈希查询 DHT
   - 获取文件提供者列表
   - 验证文件元数据

3. **文件传输**
   - 分块请求文件数据
   - 处理文件块响应
   - 验证数据完整性

## 6. 注意事项

1. **数据完整性**
   - 验证文件哈希
   - 检查数据块顺序
   - 处理传输错误

2. **性能优化**
   - 实现并发下载
   - 使用数据缓存
   - 优化块大小

3. **安全性**
   - 验证文件提供者
   - 加密文件传输
   - 防止恶意数据

## 7. 扩展建议

1. **添加更多功能**
   - 文件分片
   - 断点续传
   - 文件预览

2. **增强可靠性**
   - 多源下载
   - 数据修复
   - 传输重试

3. **改进用户体验**
   - 下载进度显示
   - 文件搜索
   - 传输速度控制 