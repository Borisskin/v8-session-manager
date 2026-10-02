//! Локальный обмен между процессами: Unix-сокеты в Linux, именованные каналы в Windows.
//!
//! Модуль не знает про HTTP, Axum и прикладные типы: он открывает слушатель, принимает и
//! устанавливает соединения и решает, кто на другом конце и можно ли ему доверять. Файлы
//! модуля одинаковы в `b-1c-masking-service` и `b-v8-session-manager` (общий крейт запрещён),
//! поэтому правятся только синхронно в обоих репозиториях.
//!
//! Инварианты: любая неопределённость (нет PID, SID, процесс завершился, нет доступа к
//! сведениям) — отказ, разрешающего значения по умолчанию нет; слушатель не возвращается из
//! [`Listener::bind`], пока права не применены; запасного адреса (TCP) нет; получатель читает
//! ответ до закрытия, пишущий последним вызывает `flush`, полузакрытие потока не используется.
//! Данные запросов в журнал не попадают.

use std::io;
use std::path::{Path, PathBuf};

#[cfg(any(windows, test))]
mod policy;
#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

#[cfg(unix)]
use unix as platform;
#[cfg(windows)]
use windows as platform;

pub use platform::{connect, Listener, Stream};

#[cfg(test)]
mod tests;

/// Адрес локальной точки связи.
///
/// Unix: абсолютный путь сокета. Windows: имя канала вида `\.\pipe\<имя>`; удалённые имена
/// (`\host\pipe\...`), `/` и вложенные разделители отвергаются.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint(PathBuf);

/// Адрес не подходит для текущей ОС. Исходное значение в сообщение не попадает.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum EndpointError {
    /// Unix: путь сокета должен быть абсолютным.
    #[error("адрес должен быть абсолютным путём сокета")]
    NotAbsolute,
    /// Windows: ожидается локальное имя вида `\.\pipe\<имя>`.
    #[error(r"адрес должен быть локальным именем канала вида \\.\pipe\<имя>")]
    NotLocalPipeName,
}

impl Endpoint {
    /// Разбирает и проверяет значение конфигурации по правилам текущей ОС.
    pub fn parse(value: &Path) -> Result<Self, EndpointError> {
        #[cfg(unix)]
        {
            if !value.is_absolute() {
                return Err(EndpointError::NotAbsolute);
            }
        }
        #[cfg(windows)]
        {
            policy::pipe_name(&value.to_string_lossy()).ok_or(EndpointError::NotLocalPipeName)?;
        }
        Ok(Self(value.to_path_buf()))
    }

    /// Адрес в исходном виде (для журнала событий и ошибок).
    pub fn as_path(&self) -> &Path {
        &self.0
    }
}

impl std::fmt::Display for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.display().fmt(f)
    }
}

/// Значение конфигурации не подходит для текущей ОС. Исходное значение в сообщение не попадает.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ConfigError {
    /// Поле принадлежит другой ОС (UID в Windows, SID и exe в Linux).
    #[error("параметр {field} не поддерживается на этой ОС")]
    Unsupported {
        /// Название поля.
        field: &'static str,
    },
    /// Обязательное поле не задано.
    #[error("параметр {field} обязателен")]
    Missing {
        /// Название поля.
        field: &'static str,
    },
    /// Поле задано, но имеет недопустимый вид.
    #[error("параметр {field} имеет недопустимое значение")]
    Invalid {
        /// Название поля.
        field: &'static str,
    },
}

/// Ожидаемая сторона соединения: учётная запись и, на Windows, исполняемый файл.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Peer {
    #[cfg_attr(windows, allow(dead_code))]
    uid: Option<u32>,
    #[cfg_attr(unix, allow(dead_code))]
    sid: Option<String>,
    #[cfg_attr(unix, allow(dead_code))]
    exe: Option<PathBuf>,
}

impl Peer {
    /// Собирает ожидаемую сторону из значений конфигурации.
    ///
    /// `uid` допустим только в Unix и обязателен там; `sid` и `exe` — только в Windows.
    /// `exe` в Windows обязателен, `sid` по умолчанию равен SID текущего процесса. Поле чужой
    /// ОС — ошибка, а не молчаливое игнорирование.
    pub fn from_config(
        uid: Option<u32>,
        sid: Option<&str>,
        exe: Option<&Path>,
    ) -> Result<Self, ConfigError> {
        #[cfg(unix)]
        {
            if sid.is_some() {
                return Err(ConfigError::Unsupported { field: "sid" });
            }
            if exe.is_some() {
                return Err(ConfigError::Unsupported { field: "exe" });
            }
            let uid = uid.ok_or(ConfigError::Missing { field: "uid" })?;
            Ok(Self { uid: Some(uid), sid: None, exe: None })
        }
        #[cfg(windows)]
        {
            if uid.is_some() {
                return Err(ConfigError::Unsupported { field: "uid" });
            }
            let exe = exe.ok_or(ConfigError::Missing { field: "exe" })?;
            if !exe.is_absolute() {
                return Err(ConfigError::Invalid { field: "exe" });
            }
            let sid = match sid {
                Some(sid) => {
                    policy::validate_sid(sid).map_err(|_| ConfigError::Invalid { field: "sid" })?;
                    sid.to_owned()
                }
                None => platform::current_sid().map_err(|_| ConfigError::Invalid { field: "sid" })?,
            };
            Ok(Self { uid: None, sid: Some(sid), exe: Some(exe.to_path_buf()) })
        }
    }

    /// Текущий процесс: его учётная запись и (на Windows) его `.exe`. Нужен административной
    /// команде, где клиент и сервер — один и тот же файл.
    pub fn current_process() -> io::Result<Self> {
        platform::current_process()
    }
}

/// Кто и как может подключаться к слушателю.
#[derive(Debug, Clone, Default)]
pub struct Access {
    /// Unix: права файла сокета (служба `0o660`, административный канал `0o600`); `None` —
    /// оставить права по `umask`. В Windows игнорируется.
    pub unix_mode: Option<u32>,
    /// Кому разрешено подключаться. `None`: Unix — UID не проверяется (защита только правами
    /// файла); Windows — только учётная запись текущего процесса.
    pub allow: Option<Peer>,
}

/// Сведения о подключившейся стороне, вычисленные при приёме соединения.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerInfo {
    /// Unix: UID совпал с `allow` (либо `allow` не задан). Windows: соединение прошло список
    /// доступа канала. Не удалось определить — `false`. Отказ обрабатывает вызывающий.
    pub authorized: bool,
}

/// Подключение не состоялось.
#[derive(Debug, thiserror::Error)]
pub enum ConnectError {
    /// Ошибка ввода-вывода при подключении.
    #[error("ошибка подключения: {0}")]
    Io(#[from] io::Error),
    /// Сервер не соответствует ожидаемому, либо соответствие проверить не удалось.
    #[error("сервер не подтверждён как доверенный")]
    Untrusted,
}
