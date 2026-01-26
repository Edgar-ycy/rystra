/// 消息编解码
use rystra_model::{Error, Result};
use rystra_proto::Message;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};


pub async fn read_message<R: AsyncRead + Unpin>(reader: &mut BufReader<R>) -> Result<Message> {
    let mut line = String::new();
    let n = reader
        .read_line(&mut line)
        .await
        .map_err(|e| Error::protocol(format!("failed to read message: {}", e)))?;

    if n == 0 {
        return Err(Error::protocol("connection closed"));
    }

    let msg: Message = serde_json::from_str(line.trim())
        .map_err(|e| Error::protocol(format!("failed to parse message: {}", e)))?;

    Ok(msg)
}

pub async fn write_message<W: AsyncWrite + Unpin>(writer: &mut W, msg: &Message) -> Result<()> {
    let json = serde_json::to_string(msg)
        .map_err(|e| Error::protocol(format!("failed to serialize message: {}", e)))?;

    writer
        .write_all(json.as_bytes())
        .await
        .map_err(|e| Error::protocol(format!("failed to write message: {}", e)))?;

    writer
        .write_all(b"\n")
        .await
        .map_err(|e| Error::protocol(format!("failed to write newline: {}", e)))?;

    writer
        .flush()
        .await
        .map_err(|e| Error::protocol(format!("failed to flush: {}", e)))?;

    Ok(())
}
