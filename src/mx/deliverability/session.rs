use std::io::{self, BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use super::types::{AttemptStage, SmtpReply};

pub(crate) struct SmtpSession {
    stream: TcpStream,
    reader: BufReader<TcpStream>,
}

impl SmtpSession {
    pub(crate) fn connect(
        addrs: &[SocketAddr],
        connect_timeout: Duration,
        command_timeout: Duration,
    ) -> io::Result<(Self, SocketAddr)> {
        let mut last_err = None;
        for addr in addrs {
            match TcpStream::connect_timeout(addr, connect_timeout) {
                Ok(stream) => {
                    stream.set_read_timeout(Some(command_timeout))?;
                    stream.set_write_timeout(Some(command_timeout))?;
                    let reader = BufReader::new(stream.try_clone()?);
                    let session = Self { stream, reader };
                    return Ok((session, *addr));
                }
                Err(err) => last_err = Some(err),
            }
        }
        Err(last_err.unwrap_or_else(|| {
            io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "no socket address available",
            )
        }))
    }

    pub(crate) fn send_command(&mut self, command: &str, stage: AttemptStage) -> io::Result<()> {
        let mut line = command.as_bytes().to_vec();
        line.extend_from_slice(b"\r\n");
        self.stream.write_all(&line)?;
        self.stream.flush()?;
        if matches!(stage, AttemptStage::Quit | AttemptStage::Rset) {
            // responses will be read explicitly; nothing to do here.
        }
        Ok(())
    }

    pub(crate) fn read_reply(&mut self) -> io::Result<SmtpReply> {
        let mut code = None;
        let mut message_lines = Vec::new();
        loop {
            let mut raw = String::new();
            let bytes = self.reader.read_line(&mut raw)?;
            if bytes == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "connection closed while reading reply",
                ));
            }
            if raw.ends_with('\n') {
                raw.pop();
                if raw.ends_with('\r') {
                    raw.pop();
                }
            }

            if raw.len() < 3 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid SMTP reply: '{raw}'"),
                ));
            }
            let code_part = &raw[..3];
            let parsed_code = code_part.parse::<u16>().map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid SMTP status code: '{code_part}'"),
                )
            })?;
            if let Some(existing) = code {
                if existing != parsed_code {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "inconsistent SMTP reply codes: {} vs {}",
                            existing, parsed_code
                        ),
                    ));
                }
            } else {
                code = Some(parsed_code);
            }
            let continuation = raw.as_bytes().get(3).copied() == Some(b'-');
            let text_start = if raw.len() > 3 { 4 } else { 3 };
            let text = if raw.len() > text_start {
                raw[text_start..].to_string()
            } else {
                String::new()
            };
            message_lines.push(text);
            if !continuation {
                break;
            }
        }
        Ok(SmtpReply {
            code: code.ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "SMTP reply missing status code")
            })?,
            message: message_lines.join("\n"),
        })
    }
}
