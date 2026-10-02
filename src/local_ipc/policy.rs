//! Чистые правила Windows-адаптера: разбор имени канала, проверка SID, сборка SDDL, решение о
//! доверии. Без ввода-вывода и вызовов ОС, поэтому проверяются тестами на любой платформе.

use std::io;

const PIPE_PREFIX: &str = r"\\.\pipe\";

/// Возвращает имя канала из `\\.\pipe\<имя>`. Удалённые имена, `/`, вложенные разделители и
/// управляющие символы отвергаются.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn pipe_name(value: &str) -> Option<&str> {
    let head = value.get(..PIPE_PREFIX.len())?;
    if !head.eq_ignore_ascii_case(PIPE_PREFIX) {
        return None;
    }
    let name = &value[PIPE_PREFIX.len()..];
    if name.is_empty() || name.chars().any(|c| matches!(c, '\\' | '/' | ':') || c.is_control()) {
        return None;
    }
    Some(name)
}

/// Проверяет строковый вид SID (`S-1-<цифры>-...`). Допустимое значение безопасно вставлять в
/// SDDL: скобки, точки с запятой и пробелы отвергаются.
pub(crate) fn validate_sid(sid: &str) -> io::Result<()> {
    let bad = || Err(io::Error::new(io::ErrorKind::InvalidInput, "недопустимый SID"));
    let Some(rest) = sid.strip_prefix("S-1-") else {
        return bad();
    };
    let parts: Vec<&str> = rest.split('-').collect();
    if parts.len() < 2 || parts.iter().any(|p| p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()))
    {
        return bad();
    }
    Ok(())
}

/// SDDL списка доступа канала: полный доступ владельцу, чтение и запись — разрешённому пиру
/// (если это другая запись). Права создавать экземпляры канала пир не получает.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn pipe_sddl(own: &str, peer: Option<&str>) -> io::Result<String> {
    validate_sid(own)?;
    let mut sddl = format!("O:{own}D:P(A;;GA;;;{own})");
    if let Some(peer) = peer.filter(|peer| *peer != own) {
        validate_sid(peer)?;
        sddl.push_str(&format!("(A;;GRGW;;;{peer})"));
    }
    Ok(sddl)
}

/// Решение о доверии к серверу: SID совпал и файл тот же. Любое недостающее сведение — отказ.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn server_trusted(
    expected_sid: &str,
    actual_sid: Option<&str>,
    same_exe: Option<bool>,
) -> bool {
    actual_sid == Some(expected_sid) && same_exe == Some(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SID: &str = "S-1-5-21-1-2-3-1001";
    const OTHER: &str = "S-1-5-21-1-2-3-1002";

    #[test]
    fn pipe_name_accepts_only_local_flat_names() {
        assert_eq!(pipe_name(r"\\.\pipe\1c-masking-service"), Some("1c-masking-service"));
        assert_eq!(pipe_name(r"\\.\PIPE\x"), Some("x"));
        for bad in [
            "",
            r"\\.\pipe\",
            r"\\.\pipe\a\b",
            r"\\.\pipe\a/b",
            r"\\server\pipe\x",
            r"\\?\pipe\x",
            "/run/x.sock",
            "plain",
            "\\\\.\\pipe\\a\u{0}",
        ] {
            assert_eq!(pipe_name(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn sddl_grants_peer_read_write_without_instance_creation() {
        let own_only = pipe_sddl(SID, None).unwrap();
        assert_eq!(own_only, format!("O:{SID}D:P(A;;GA;;;{SID})"));
        assert_eq!(pipe_sddl(SID, Some(SID)).unwrap(), own_only);
        let both = pipe_sddl(SID, Some(OTHER)).unwrap();
        assert_eq!(both, format!("O:{SID}D:P(A;;GA;;;{SID})(A;;GRGW;;;{OTHER})"));
        for forbidden in ["WD", "AN", "AU", "BU", "IU", "BA", "SY"] {
            assert!(!both.contains(forbidden), "{both}");
        }
    }

    #[test]
    fn sid_validation_rejects_injection() {
        for bad in [
            "",
            " ",
            "S-1-5",
            "S-1-5-21-1-2-3-1001 ",
            "S-1-5-1;WD",
            "S-1-5-1)",
            "S-1-5-a",
            "X-1-5-1-2",
        ] {
            assert!(validate_sid(bad).is_err(), "{bad:?}");
            assert!(pipe_sddl(SID, Some(bad)).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn trust_requires_every_fact() {
        assert!(server_trusted(SID, Some(SID), Some(true)));
        assert!(!server_trusted(SID, Some(OTHER), Some(true)));
        assert!(!server_trusted(SID, Some(SID), Some(false)));
        assert!(!server_trusted(SID, None, Some(true)));
        assert!(!server_trusted(SID, Some(SID), None));
    }
}
