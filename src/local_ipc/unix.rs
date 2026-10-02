//! Адаптер Unix: прежние `tokio::net::Unix*` без изменения поведения.

use std::fs;
use std::io;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::Path;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{UnixListener, UnixStream};

use super::{Access, ConnectError, Endpoint, Peer, PeerInfo};

/// Двунаправленный поток соединения.
#[derive(Debug)]
pub struct Stream(UnixStream);

impl AsyncRead for Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write_vectored(cx, bufs)
    }
    fn is_write_vectored(&self) -> bool {
        self.0.is_write_vectored()
    }
}

/// Слушатель локальной точки связи.
#[derive(Debug)]
pub struct Listener {
    inner: UnixListener,
    endpoint: Endpoint,
    /// `None` — UID не проверяется; `Some(None)` — пир задан без UID (всё отвергается).
    allow_uid: Option<Option<u32>>,
}

impl Listener {
    /// Синхронно и fail-closed: создаёт каталог, убирает устаревший сокет (только если это
    /// сокет), создаёт слушатель, применяет права. Занятое имя и не-сокет по пути — ошибка.
    pub fn bind(endpoint: &Endpoint, access: Access) -> io::Result<Self> {
        let path = endpoint.as_path();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        remove_stale_socket(path)?;
        let inner = UnixListener::bind(path)?;
        if let Some(mode) = access.unix_mode {
            fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
        }
        Ok(Self {
            inner,
            endpoint: endpoint.clone(),
            allow_uid: access.allow.map(|peer| peer.uid),
        })
    }

    /// Принимает соединение и вычисляет [`PeerInfo`]. Отказ обрабатывает вызывающий.
    pub async fn accept(&mut self) -> io::Result<(Stream, PeerInfo)> {
        let (stream, _) = self.inner.accept().await?;
        let authorized = match self.allow_uid {
            None => true,
            Some(expected) => match (expected, stream.peer_cred()) {
                (Some(expected), Ok(cred)) => cred.uid() == expected,
                _ => false,
            },
        };
        Ok((Stream(stream), PeerInfo { authorized }))
    }

    /// Удаляет файл сокета (корректное завершение). В Windows ничего не делает.
    pub fn close(self) {
        let _ = fs::remove_file(self.endpoint.as_path());
    }
}

fn remove_stale_socket(path: &Path) -> io::Result<()> {
    if path.exists() {
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.file_type().is_socket() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "refusing to replace a non-socket path",
            ));
        }
        fs::remove_file(path)?;
    }
    Ok(())
}

/// Подключение. `server: Some(peer)` — UID сервера обязан совпасть, иначе
/// [`ConnectError::Untrusted`]; невозможность проверить тоже отказ.
pub async fn connect(endpoint: &Endpoint, server: Option<&Peer>) -> Result<Stream, ConnectError> {
    let stream = UnixStream::connect(endpoint.as_path()).await?;
    if let Some(peer) = server {
        let trusted = match (peer.uid, stream.peer_cred()) {
            (Some(expected), Ok(cred)) => cred.uid() == expected,
            _ => false,
        };
        if !trusted {
            tracing::warn!(event = "ipc_server_untrusted", endpoint = %endpoint);
            return Err(ConnectError::Untrusted);
        }
    }
    Ok(Stream(stream))
}

pub(super) fn current_process() -> io::Result<Peer> {
    // SAFETY: geteuid has no arguments, does not dereference memory, and has no failure mode.
    let uid = unsafe { libc::geteuid() };
    Ok(Peer { uid: Some(uid), sid: None, exe: None })
}
