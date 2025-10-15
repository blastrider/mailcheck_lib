use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use native_tls::{HandshakeError, TlsConnector, TlsStream};

use crate::smtp_verify::error::SmtpVerifyError;

#[derive(Debug, Clone)]
pub struct SmtpReply {
    pub code: u16,
    pub lines: Vec<String>,
}

impl SmtpReply {
    pub fn is_positive_completion(&self) -> bool {
        (200..300).contains(&self.code)
    }

    pub fn is_transient_failure(&self) -> bool {
        (400..500).contains(&self.code)
    }

    pub fn is_permanent_failure(&self) -> bool {
        (500..600).contains(&self.code)
    }

    pub fn has_capability(&self, cap: &str) -> bool {
        let upper = cap.to_ascii_uppercase();
        self.lines.iter().any(|line| {
            line.split_whitespace()
                .next()
                .map(|token| token.eq_ignore_ascii_case(&upper))
                .unwrap_or(false)
        })
    }
}

#[derive(Debug)]
enum StreamState {
    Plain(TcpStream),
    Tls(TlsStream<TcpStream>),
    Invalid,
}

#[derive(Debug)]
pub struct SmtpStream {
    state: StreamState,
    buffer: Vec<u8>,
}

impl SmtpStream {
    pub fn connect(addr: &SocketAddr, timeout: Option<Duration>) -> Result<Self, SmtpVerifyError> {
        let stream = if let Some(timeout) = timeout {
            TcpStream::connect_timeout(addr, timeout).map_err(|err| SmtpVerifyError::Connect {
                host: addr.to_string(),
                source: err,
            })?
        } else {
            TcpStream::connect(addr).map_err(|err| SmtpVerifyError::Connect {
                host: addr.to_string(),
                source: err,
            })?
        };
        stream
            .set_read_timeout(timeout)
            .map_err(|err| SmtpVerifyError::Io { source: err })?;
        stream
            .set_write_timeout(timeout)
            .map_err(|err| SmtpVerifyError::Io { source: err })?;
        Ok(Self {
            state: StreamState::Plain(stream),
            buffer: Vec::new(),
        })
    }

    pub fn upgrade_tls(
        &mut self,
        domain: &str,
        connector: &TlsConnector,
        timeout: Option<Duration>,
    ) -> Result<(), SmtpVerifyError> {
        let mut state = StreamState::Invalid;
        std::mem::swap(&mut self.state, &mut state);
        let plain = match state {
            StreamState::Plain(stream) => stream,
            StreamState::Tls(stream) => {
                self.state = StreamState::Tls(stream);
                return Ok(());
            }
            StreamState::Invalid => unreachable!(),
        };

        let mut tls = complete_handshake(connector, domain, plain)?;
        if let Some(timeout) = timeout {
            tls.get_mut()
                .set_read_timeout(Some(timeout))
                .map_err(|err| SmtpVerifyError::Io { source: err })?;
            tls.get_mut()
                .set_write_timeout(Some(timeout))
                .map_err(|err| SmtpVerifyError::Io { source: err })?;
        }
        self.state = StreamState::Tls(tls);
        Ok(())
    }

    pub fn send_command(&mut self, command: &str) -> Result<(), SmtpVerifyError> {
        let mut data = command.as_bytes().to_vec();
        data.extend_from_slice(b"\r\n");
        self.write_all(&data)
    }

    pub fn write_all(&mut self, data: &[u8]) -> Result<(), SmtpVerifyError> {
        match &mut self.state {
            StreamState::Plain(stream) => {
                stream
                    .write_all(data)
                    .map_err(|err| SmtpVerifyError::Io { source: err })?;
                stream
                    .flush()
                    .map_err(|err| SmtpVerifyError::Io { source: err })?
            }
            StreamState::Tls(stream) => {
                stream
                    .write_all(data)
                    .map_err(|err| SmtpVerifyError::Io { source: err })?;
                stream
                    .flush()
                    .map_err(|err| SmtpVerifyError::Io { source: err })?
            }
            StreamState::Invalid => {
                return Err(SmtpVerifyError::Protocol("invalid stream state".into()));
            }
        }
        Ok(())
    }

    pub fn read_reply(&mut self) -> Result<SmtpReply, SmtpVerifyError> {
        let mut lines = Vec::new();
        let mut code: Option<u16> = None;
        loop {
            let line = self.read_line()?;
            if line.len() < 3 {
                return Err(SmtpVerifyError::Protocol(format!("invalid reply: {line}")));
            }
            let parsed_code = line[..3]
                .parse::<u16>()
                .map_err(|_| SmtpVerifyError::Protocol(format!("invalid code in line: {line}")))?;
            if let Some(existing) = code {
                if existing != parsed_code {
                    return Err(SmtpVerifyError::Protocol(format!(
                        "inconsistent reply codes: {existing} vs {parsed_code}"
                    )));
                }
            } else {
                code = Some(parsed_code);
            }
            let is_last = !line.as_bytes().get(3).map(|b| *b == b'-').unwrap_or(false);
            let text = if line.len() > 4 {
                line[4..].to_string()
            } else {
                String::new()
            };
            lines.push(text);
            if is_last {
                break;
            }
        }
        Ok(SmtpReply {
            code: code.unwrap_or(0),
            lines,
        })
    }

    fn read_line(&mut self) -> Result<String, SmtpVerifyError> {
        loop {
            if let Some(pos) = self.buffer.iter().position(|byte| *byte == b'\n') {
                let mut line = self.buffer.drain(..=pos).collect::<Vec<_>>();
                if line.ends_with(b"\r\n") {
                    line.truncate(line.len() - 2);
                } else if line.ends_with(b"\n") {
                    line.truncate(line.len() - 1);
                }
                return String::from_utf8(line)
                    .map_err(|err| SmtpVerifyError::Protocol(format!("utf8 error: {err}")));
            }

            let mut buf = [0u8; 512];
            let read = match &mut self.state {
                StreamState::Plain(stream) => stream.read(&mut buf),
                StreamState::Tls(stream) => stream.read(&mut buf),
                StreamState::Invalid => {
                    return Err(SmtpVerifyError::Protocol("invalid stream state".into()));
                }
            };
            let read = read.map_err(|err| SmtpVerifyError::Io { source: err })?;
            if read == 0 {
                return Err(SmtpVerifyError::Io {
                    source: io::Error::new(io::ErrorKind::UnexpectedEof, "connection closed"),
                });
            }
            self.buffer.extend_from_slice(&buf[..read]);
        }
    }
}

fn complete_handshake(
    connector: &TlsConnector,
    domain: &str,
    stream: TcpStream,
) -> Result<TlsStream<TcpStream>, SmtpVerifyError> {
    match connector.connect(domain, stream) {
        Ok(tls) => Ok(tls),
        Err(HandshakeError::Failure(err)) => Err(SmtpVerifyError::Tls { source: err }),
        Err(HandshakeError::WouldBlock(mut mid)) => loop {
            match mid.handshake() {
                Ok(tls) => break Ok(tls),
                Err(HandshakeError::Failure(err)) => {
                    break Err(SmtpVerifyError::Tls { source: err });
                }
                Err(HandshakeError::WouldBlock(next)) => mid = next,
            }
        },
    }
}

pub struct SmtpSession {
    host: String,
    pub stream: SmtpStream,
    pub transcript: Vec<String>,
}

impl SmtpSession {
    pub fn connect(
        host: &str,
        addresses: &[SocketAddr],
        timeout: Option<Duration>,
    ) -> Result<Self, SmtpVerifyError> {
        let mut last_err = None;
        for addr in addresses {
            match SmtpStream::connect(addr, timeout) {
                Ok(stream) => {
                    return Ok(Self {
                        host: host.to_string(),
                        stream,
                        transcript: Vec::new(),
                    });
                }
                Err(err) => last_err = Some(err),
            }
        }
        Err(last_err.unwrap_or(SmtpVerifyError::NoSmtpServers))
    }

    pub fn record(&mut self, direction: &str, message: &str) {
        self.transcript
            .push(format!("[{}] {direction}: {message}", self.host));
    }

    pub fn read_banner(&mut self) -> Result<SmtpReply, SmtpVerifyError> {
        let reply = self.stream.read_reply()?;
        self.record_reply(&reply);
        Ok(reply)
    }

    pub fn send_command(&mut self, command: &str) -> Result<SmtpReply, SmtpVerifyError> {
        self.record("C", command);
        self.stream.send_command(command)?;
        let reply = self.stream.read_reply()?;
        self.record_reply(&reply);
        Ok(reply)
    }

    pub fn starttls(
        &mut self,
        domain: &str,
        connector: &TlsConnector,
        timeout: Option<Duration>,
    ) -> Result<SmtpReply, SmtpVerifyError> {
        let reply = self.send_command("STARTTLS")?;
        if !reply.is_positive_completion() {
            return Ok(reply);
        }
        self.stream.upgrade_tls(domain, connector, timeout)?;
        Ok(reply)
    }

    pub fn quit(&mut self) -> Result<(), SmtpVerifyError> {
        self.record("C", "QUIT");
        self.stream.send_command("QUIT")?;
        if let Ok(reply) = self.stream.read_reply() {
            self.record_reply(&reply);
        }
        Ok(())
    }

    fn record_reply(&mut self, reply: &SmtpReply) {
        if reply.lines.is_empty() {
            self.record("S", &format!("{}", reply.code));
        } else {
            for line in &reply.lines {
                self.record("S", &format!("{} {}", reply.code, line));
            }
        }
    }
}
