//! rystra-runtime: 运行时抽象模块
//!
//! 规划功能：
//! - 任务管理
//! - 超时控制
//! - 重连策略
//!
use rystra_plugin::TransportStream;
use std::pin::Pin;
use tokio::io::{AsyncRead, AsyncWrite, ReadHalf, WriteHalf};
type DynReader = ReadHalf<Box<dyn TransportStream>>;
type DynWriter = WriteHalf<Box<dyn TransportStream>>;

pub struct ReunitedStream {
    reader: DynReader,
    writer: DynWriter,
}

impl ReunitedStream {
    pub fn new(reader: DynReader, writer: DynWriter) -> Self {
        Self { reader, writer }
    }
}

impl AsyncRead for ReunitedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        Pin::new(&mut self.reader).poll_read(cx, buf)
    }
}

impl AsyncWrite for ReunitedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        Pin::new(&mut self.writer).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        Pin::new(&mut self.writer).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        Pin::new(&mut self.writer).poll_shutdown(cx)
    }
}

impl TransportStream for ReunitedStream {}