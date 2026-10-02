//! Набор проверок интерфейса `local_ipc`: одинаков на обеих ОС, платформенна только функция
//! создания адреса и ожидаемые «верный» и «неверный» пир.

use std::path::Path;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;

struct TestEndpoint {
    endpoint: Endpoint,
    _dir: Option<tempfile::TempDir>,
}

#[cfg(unix)]
fn test_endpoint() -> TestEndpoint {
    let dir = tempfile::tempdir().unwrap();
    let endpoint = Endpoint::parse(&dir.path().join("ipc.sock")).unwrap();
    TestEndpoint { endpoint, _dir: Some(dir) }
}

#[cfg(windows)]
fn test_endpoint() -> TestEndpoint {
    use std::sync::atomic::{AtomicU32, Ordering};
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let name = format!(
        r"\\.\pipe\local-ipc-test-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    );
    TestEndpoint { endpoint: Endpoint::parse(Path::new(&name)).unwrap(), _dir: None }
}

/// Пир, под которого подходит сервер этого теста (сам процесс).
fn right_peer() -> Peer {
    Peer::current_process().unwrap()
}

/// Пир, под которого сервер этого теста не подходит.
fn wrong_peer() -> Peer {
    #[cfg(unix)]
    {
        Peer { uid: right_peer().uid.map(|uid| uid + 1_000), sid: None, exe: None }
    }
    #[cfg(windows)]
    {
        let mut peer = right_peer();
        peer.exe = Some(std::path::PathBuf::from(r"C:\Windows\System32\cmd.exe"));
        peer
    }
}

fn bind(endpoint: &Endpoint) -> Listener {
    Listener::bind(endpoint, Access::default()).unwrap()
}

/// Сервер читает запрос до пустой строки, отвечает и сразу закрывает поток.
async fn serve_once(mut listener: Listener) {
    let (mut stream, info) = listener.accept().await.unwrap();
    assert!(info.authorized);
    let mut request = Vec::new();
    let mut chunk = [0u8; 256];
    while !request.ends_with(b"\r\n\r\n") {
        let n = stream.read(&mut chunk).await.unwrap();
        assert!(n > 0, "клиент закрыл поток до конца запроса");
        request.extend_from_slice(&chunk[..n]);
    }
    stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").await.unwrap();
    stream.flush().await.unwrap();
}

#[tokio::test]
async fn response_written_before_close_arrives_whole() {
    let t = test_endpoint();
    let server = tokio::spawn(serve_once(bind(&t.endpoint)));
    let mut client = connect(&t.endpoint, None).await.unwrap();
    client.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").await.unwrap();
    client.flush().await.unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();
    assert!(response.ends_with(b"\r\n\r\nok"), "{}", String::from_utf8_lossy(&response));
    server.await.unwrap();
}

#[tokio::test]
async fn several_exchanges_on_one_connection_without_eof() {
    let t = test_endpoint();
    let mut listener = bind(&t.endpoint);
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        // Эхо блоками фиксированной длины: границы сообщений задаёт длина, а не EOF.
        let mut block = [0u8; 8];
        for _ in 0..5 {
            stream.read_exact(&mut block).await.unwrap();
            stream.write_all(&block).await.unwrap();
            stream.flush().await.unwrap();
        }
    });
    let mut client = connect(&t.endpoint, None).await.unwrap();
    for i in 0..5u8 {
        client.write_all(&[i; 8]).await.unwrap();
        let mut back = [0u8; 8];
        client.read_exact(&mut back).await.unwrap();
        assert_eq!(back, [i; 8]);
    }
    server.await.unwrap();
}

#[tokio::test]
async fn large_body_passes_both_ways() {
    const SIZE: usize = 1024 * 1024;
    let t = test_endpoint();
    let mut listener = bind(&t.endpoint);
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let (mut read, mut write) = tokio::io::split(stream);
        let mut body = vec![0u8; SIZE];
        read.read_exact(&mut body).await.unwrap();
        write.write_all(&body).await.unwrap();
        write.flush().await.unwrap();
    });
    let client = connect(&t.endpoint, None).await.unwrap();
    let (mut read, mut write) = tokio::io::split(client);
    let body: Vec<u8> = (0..SIZE).map(|i| (i % 251) as u8).collect();
    let ((), received) = tokio::join!(
        async {
            write.write_all(&body).await.unwrap();
            write.flush().await.unwrap();
        },
        async {
            let mut back = vec![0u8; SIZE];
            read.read_exact(&mut back).await.unwrap();
            back
        }
    );
    assert_eq!(received, body);
    server.await.unwrap();
}

#[tokio::test]
async fn client_abort_mid_request_does_not_break_listener() {
    let t = test_endpoint();
    let mut listener = bind(&t.endpoint);
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 64];
        // Обрыв клиента — обычное закрытие либо ошибка чтения, но не зависание.
        tokio::time::timeout(Duration::from_secs(5), async {
            while matches!(stream.read(&mut buf).await, Ok(n) if n > 0) {}
        })
        .await
        .expect("сервер завис после обрыва клиента");
        let (mut stream, _) = listener.accept().await.unwrap();
        stream.write_all(b"again").await.unwrap();
        stream.flush().await.unwrap();
    });
    let mut first = connect(&t.endpoint, None).await.unwrap();
    first.write_all(b"POST / HTTP/1.1\r\nContent-Le").await.unwrap();
    first.flush().await.unwrap();
    drop(first);
    let mut second = connect(&t.endpoint, None).await.unwrap();
    let mut reply = Vec::new();
    second.read_to_end(&mut reply).await.unwrap();
    assert_eq!(reply, b"again");
    server.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sixty_four_parallel_connections() {
    const N: usize = 64;
    let t = test_endpoint();
    let mut listener = bind(&t.endpoint);
    let server = tokio::spawn(async move {
        let mut handlers = Vec::new();
        for _ in 0..N {
            let (mut stream, _) = listener.accept().await.unwrap();
            handlers.push(tokio::spawn(async move {
                let mut byte = [0u8; 1];
                stream.read_exact(&mut byte).await.unwrap();
                stream.write_all(&byte).await.unwrap();
                stream.flush().await.unwrap();
            }));
        }
        for handler in handlers {
            handler.await.unwrap();
        }
    });
    let mut clients = Vec::new();
    for i in 0..N {
        let endpoint = t.endpoint.clone();
        clients.push(tokio::spawn(async move {
            let mut stream = connect(&endpoint, None).await.expect("подключение отвергнуто");
            stream.write_all(&[i as u8]).await.unwrap();
            stream.flush().await.unwrap();
            let mut back = [0u8; 1];
            stream.read_exact(&mut back).await.unwrap();
            assert_eq!(back[0], i as u8);
        }));
    }
    for client in clients {
        client.await.unwrap();
    }
    server.await.unwrap();
}

#[tokio::test]
async fn connect_checks_server_identity() {
    let t = test_endpoint();
    let mut listener = bind(&t.endpoint);
    let server = tokio::spawn(async move {
        for _ in 0..3 {
            let _ = listener.accept().await.unwrap();
        }
    });
    assert!(connect(&t.endpoint, Some(&right_peer())).await.is_ok());
    assert!(matches!(
        connect(&t.endpoint, Some(&wrong_peer())).await,
        Err(ConnectError::Untrusted)
    ));
    // Пир без нужных сведений: проверить нельзя — значит отказ.
    let unknown = Peer { uid: None, sid: None, exe: None };
    assert!(matches!(connect(&t.endpoint, Some(&unknown)).await, Err(ConnectError::Untrusted)));
    server.await.unwrap();
}

#[tokio::test]
async fn connect_without_expected_server_does_not_check_identity() {
    let t = test_endpoint();
    let mut listener = bind(&t.endpoint);
    let server = tokio::spawn(async move { listener.accept().await.unwrap() });
    assert!(connect(&t.endpoint, None).await.is_ok());
    let _ = server.await.unwrap();
}

#[tokio::test]
async fn connect_to_missing_endpoint_is_io_error() {
    let t = test_endpoint();
    assert!(matches!(connect(&t.endpoint, None).await, Err(ConnectError::Io(_))));
}

#[cfg(unix)]
#[tokio::test]
async fn authorized_follows_allowed_uid() {
    for (allow, expected) in [(right_peer(), true), (wrong_peer(), false)] {
        let t = test_endpoint();
        let access = Access { unix_mode: Some(0o600), allow: Some(allow) };
        let mut listener = Listener::bind(&t.endpoint, access).unwrap();
        let client = tokio::spawn({
            let endpoint = t.endpoint.clone();
            async move { connect(&endpoint, None).await.unwrap() }
        });
        let (_stream, info) = listener.accept().await.unwrap();
        assert_eq!(info.authorized, expected);
        let _ = client.await.unwrap();
    }
    // Без `allow` UID не проверяется.
    let t = test_endpoint();
    let mut listener = bind(&t.endpoint);
    let _client = connect(&t.endpoint, None).await.unwrap();
    assert!(listener.accept().await.unwrap().1.authorized);
}

#[cfg(unix)]
#[tokio::test]
async fn bind_applies_mode_and_refuses_non_socket() {
    use std::os::unix::fs::PermissionsExt;
    let t = test_endpoint();
    let access = Access { unix_mode: Some(0o600), allow: None };
    let listener = Listener::bind(&t.endpoint, access).unwrap();
    let mode = std::fs::metadata(t.endpoint.as_path()).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
    listener.close();
    assert!(!t.endpoint.as_path().exists());

    std::fs::write(t.endpoint.as_path(), b"data").unwrap();
    assert!(Listener::bind(&t.endpoint, Access::default()).is_err());
    assert_eq!(std::fs::read(t.endpoint.as_path()).unwrap(), b"data");
}

#[cfg(windows)]
#[tokio::test]
async fn taken_name_is_an_error() {
    let t = test_endpoint();
    let _first = bind(&t.endpoint);
    let err = Listener::bind(&t.endpoint, Access::default()).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::AddrInUse);
}

#[test]
fn endpoint_parse_follows_platform_rules() {
    #[cfg(unix)]
    {
        assert!(Endpoint::parse(Path::new("/run/x.sock")).is_ok());
        assert_eq!(Endpoint::parse(Path::new("x.sock")), Err(EndpointError::NotAbsolute));
        assert_eq!(Endpoint::parse(Path::new(r"\\.\pipe\x")), Err(EndpointError::NotAbsolute));
    }
    #[cfg(windows)]
    {
        assert!(Endpoint::parse(Path::new(r"\\.\pipe\x")).is_ok());
        for bad in [r"C:\x.sock", "/run/x.sock", r"\\server\pipe\x", r"\\.\pipe\a\b"] {
            assert_eq!(
                Endpoint::parse(Path::new(bad)),
                Err(EndpointError::NotLocalPipeName),
                "{bad}"
            );
        }
    }
}

#[test]
fn peer_from_config_rejects_foreign_and_missing_fields() {
    #[cfg(unix)]
    {
        assert!(Peer::from_config(Some(1000), None, None).is_ok());
        assert_eq!(
            Peer::from_config(Some(1000), Some("S-1-5-1-2"), None),
            Err(ConfigError::Unsupported { field: "sid" })
        );
        assert_eq!(
            Peer::from_config(Some(1000), None, Some(Path::new("/bin/x"))),
            Err(ConfigError::Unsupported { field: "exe" })
        );
        assert_eq!(Peer::from_config(None, None, None), Err(ConfigError::Missing { field: "uid" }));
    }
    #[cfg(windows)]
    {
        assert_eq!(
            Peer::from_config(Some(1000), None, Some(Path::new(r"C:\x.exe"))),
            Err(ConfigError::Unsupported { field: "uid" })
        );
        assert_eq!(Peer::from_config(None, None, None), Err(ConfigError::Missing { field: "exe" }));
        assert_eq!(
            Peer::from_config(None, None, Some(Path::new("x.exe"))),
            Err(ConfigError::Invalid { field: "exe" })
        );
        assert_eq!(
            Peer::from_config(None, Some("bad"), Some(Path::new(r"C:\x.exe"))),
            Err(ConfigError::Invalid { field: "sid" })
        );
    }
}
