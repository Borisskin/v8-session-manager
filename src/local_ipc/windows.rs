//! Адаптер Windows: именованные каналы через `interprocess` (`local_socket`, Tokio).
//!
//! Канал создаётся с признаком первого экземпляра (занятое имя — ошибка), без приёма удалённых
//! клиентов и с защищённым списком доступа. Сервер при подключении проверяется по PID,
//! который сообщает канал: SID владельца процесса и тот же файл `.exe`.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use interprocess::local_socket::tokio::{Listener as PipeListener, Stream as PipeStream};
use interprocess::local_socket::traits::tokio::{Listener as _, Stream as _};
use interprocess::local_socket::traits::StreamCommon as _;
use interprocess::local_socket::{GenericNamespaced, ListenerOptions, ToNsName};
use interprocess::os::windows::local_socket::ListenerOptionsExt;
use interprocess::os::windows::security_descriptor::SecurityDescriptor;
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use widestring::U16CString;
use win_security_identifier::{GetCurrentSid, SecurityIdentifier};

use super::{policy, Access, ConnectError, Endpoint, Peer, PeerInfo};

/// Код Windows «доступ запрещён»: так `CreateNamedPipe` отвечает, когда первый экземпляр
/// канала с этим именем уже существует.
const ERROR_ACCESS_DENIED: i32 = 5;

/// Предельное время подключения к каналу, включая ожидание свободного экземпляра.
const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Двунаправленный поток соединения.
#[derive(Debug)]
pub struct Stream(PipeStream);

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
}

/// Слушатель локальной точки связи.
pub struct Listener {
    inner: PipeListener,
}

impl std::fmt::Debug for Listener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Listener").finish_non_exhaustive()
    }
}

fn pipe_name(endpoint: &Endpoint) -> io::Result<interprocess::local_socket::Name<'static>> {
    let value = endpoint.as_path().to_string_lossy();
    let name = policy::pipe_name(&value)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "недопустимое имя канала"))?;
    name.to_owned().to_ns_name::<GenericNamespaced>()
}

pub(super) fn current_sid() -> io::Result<String> {
    SecurityIdentifier::get_current_user_sid()
        .map(|sid| sid.to_string())
        .map_err(|e| io::Error::other(format!("не удалось прочитать SID текущей записи: {e}")))
}

impl Listener {
    /// Синхронно и fail-closed: создаёт канал с защищённым списком доступа. Занятое имя —
    /// ошибка `AddrInUse`, запасного адреса нет. Права применены до возврата слушателя.
    pub fn bind(endpoint: &Endpoint, access: Access) -> io::Result<Self> {
        let own = current_sid()?;
        let peer_sid = access.allow.as_ref().and_then(|peer| peer.sid.as_deref());
        let sddl = policy::pipe_sddl(&own, peer_sid)?;
        let sddl = U16CString::from_str(&sddl)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
        let descriptor = SecurityDescriptor::deserialize(sddl.as_ucstr())?;
        let inner = ListenerOptions::new()
            .name(pipe_name(endpoint)?)
            .security_descriptor(descriptor)
            .create_tokio()
            .map_err(|e| {
                if e.raw_os_error() == Some(ERROR_ACCESS_DENIED) {
                    io::Error::new(io::ErrorKind::AddrInUse, "канал с таким именем уже существует")
                } else {
                    e
                }
            })?;
        Ok(Self { inner })
    }

    /// Принимает соединение. Доступ ограничен списком доступа канала, поэтому принятое
    /// соединение авторизовано.
    pub async fn accept(&mut self) -> io::Result<(Stream, PeerInfo)> {
        let stream = self.inner.accept().await?;
        Ok((Stream(stream), PeerInfo { authorized: true }))
    }

    /// В Windows ничего не делает (файла сокета нет).
    pub fn close(self) {}
}

/// Подключение. `server: Some(peer)` — SID владельца и файл `.exe` процесса сервера обязаны
/// совпасть, иначе [`ConnectError::Untrusted`]; невозможность проверить тоже отказ.
pub async fn connect(endpoint: &Endpoint, server: Option<&Peer>) -> Result<Stream, ConnectError> {
    // `interprocess` при занятом канале ждёт свободный экземпляр без предела; подключение не
    // должно висеть вечно, поэтому время ожидания ограничено.
    let stream = tokio::time::timeout(CONNECT_TIMEOUT, PipeStream::connect(pipe_name(endpoint)?))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "время подключения к каналу истекло"))??;
    if let Some(peer) = server {
        if !verify_server(&stream, peer, endpoint) {
            return Err(ConnectError::Untrusted);
        }
    }
    Ok(Stream(stream))
}

fn verify_server(stream: &PipeStream, expected: &Peer, endpoint: &Endpoint) -> bool {
    let (Some(expected_sid), Some(expected_exe)) = (expected.sid.as_deref(), expected.exe.as_deref())
    else {
        return false;
    };
    let Some(pid) = stream.peer_creds().ok().and_then(|creds| creds.pid()) else {
        tracing::warn!(event = "ipc_server_untrusted", endpoint = %endpoint, reason = "pid_unavailable");
        return false;
    };
    let mut system = System::new();
    let kind = ProcessRefreshKind::nothing().with_exe(UpdateKind::Always).with_user(UpdateKind::Always);
    system.refresh_processes_specifics(ProcessesToUpdate::Some(&[Pid::from_u32(pid)]), true, kind);
    let process = system.process(Pid::from_u32(pid));
    let actual_sid = process.and_then(|p| p.user_id()).map(|uid| uid.to_string());
    let actual_exe = process.and_then(|p| p.exe());
    let same_exe = actual_exe.and_then(|actual| same_file::is_same_file(expected_exe, actual).ok());
    let trusted = policy::server_trusted(expected_sid, actual_sid.as_deref(), same_exe);
    if !trusted {
        // Пути и SID пишутся только в журнал отказа проверки сервера.
        tracing::warn!(
            event = "ipc_server_untrusted",
            endpoint = %endpoint,
            reason = "identity_mismatch_or_unavailable",
            expected_exe = %expected_exe.display(),
            actual_exe = ?actual_exe,
            expected_sid,
            actual_sid = ?actual_sid,
        );
    }
    trusted
}

pub(super) fn current_process() -> io::Result<Peer> {
    Ok(Peer { uid: None, sid: Some(current_sid()?), exe: Some(std::env::current_exe()?) })
}
