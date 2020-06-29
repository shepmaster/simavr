use futures::{channel::mpsc, SinkExt};
use hex::FromHex;
use itertools::Itertools;
use snafu::{ensure, ResultExt, Snafu};
use std::{
    collections::BTreeMap,
    convert::{TryFrom, TryInto},
    io, str,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufStream},
    net::{TcpListener, TcpStream},
};

use crate::{Command, Ipc};

const HOST: &str = "127.0.0.1";
const PORT: u16 = 1234;

pub(crate) async fn listen(command_tx: mpsc::Sender<Command>) -> Result<()> {
    let mut listener = TcpListener::bind((HOST, PORT))
        .await
        .context(UnableToBind)?;

    loop {
        let (socket, _) = listener.accept().await.context(UnableToAccept)?;
        let mut gdb = Gdb::new(socket, command_tx.clone());
        gdb.process().await?;
    }
}

#[derive(Debug)]
struct Gdb {
    socket: BufStream<TcpStream>,
    command_tx: mpsc::Sender<Command>,
    active_breakpoints: BTreeMap<u32, Vec<u8>>,
}

#[derive(Debug)]
enum Packet<'a> {
    Disconnected,
    Interrupt,
    Data(&'a [u8]),
}

impl Gdb {
    fn new(socket: TcpStream, command_tx: mpsc::Sender<Command>) -> Self {
        let socket = BufStream::new(socket);

        Self {
            socket,
            command_tx,
            active_breakpoints: Default::default(),
        }
    }

    async fn command(&mut self, cmd: Command) -> Result<()> {
        self.command_tx.send(cmd).await.unwrap();
        Ok(())
    }

    async fn ipc<V, A, R>(&mut self, variant: V, args: A) -> Result<R>
    where
        V: FnOnce(Ipc<A, R>) -> Command,
    {
        let (ipc, rx) = Ipc::new(args);
        self.command(variant(ipc)).await?;
        Ok(rx.await.unwrap())
    }

    async fn process(&mut self) -> Result<()> {
        let mut packet = Vec::new();

        self.validate_status_success().await?;

        eprintln!("Halting due to GDB attach");
        self.command(Command::Halt).await?;

        loop {
            let body = match self.read_packet(&mut packet).await? {
                Packet::Disconnected => return Ok(()),
                Packet::Interrupt => {
                    eprintln!("Halting due to GDB interrupt");
                    self.command(Command::Halt).await?;
                    continue;
                }
                Packet::Data(body) => body,
            };

            // let _ = dbg!(str::from_utf8(body));

            let response = self.handle_command(body).await.unwrap_or_else(|e| {
                eprintln!("Error: {}\n{:?}", e, e);
                b"".to_vec()
            });

            // let _ = dbg!(str::from_utf8(&response));

            self.respond_success(&response)
                .await
                .context(UnableToSendResponse)?;
            self.validate_status_success().await?;
        }
    }

    async fn read_packet<'a>(&mut self, packet: &'a mut Vec<u8>) -> Result<Packet<'a>> {
        packet.clear();

        let x = (&mut self.socket).take(1).read_to_end(packet).await;

        if let Err(_) = x {
            return Ok(Packet::Disconnected);
        }

        if packet[0] == 0x03 {
            // Control-C
            return Ok(Packet::Interrupt);
        }

        self.socket
            .read_until(b'#', packet)
            .await
            .context(UnableToReadPacket)?;
        (&mut self.socket)
            .take(2)
            .read_to_end(packet)
            .await
            .context(UnableToReadChecksum)?;

        //        let _ = dbg!(std::str::from_utf8(&packet));

        let (body, expected_checksum) = match &packet[..] {
            &[b'$', ref body @ .., b'#', c0, c1] => {
                let c: u8 = dehex(&[c0, c1]).context(ChecksumNotHex)?;
                (body, c)
            }

            &[head, .., tail, _, _] => PacketHasWrongEncapsulation { head, tail }.fail()?,

            _ => PacketTooShort { len: packet.len() }.fail()?,
        };

        let actual_checksum = checksum_of(&body);

        ensure!(
            expected_checksum == actual_checksum,
            ChecksumFailed {
                expected: expected_checksum,
                actual: actual_checksum
            }
        );

        Ok(Packet::Data(body))
    }

    async fn validate_status_success(&mut self) -> Result<()> {
        let mut c = [0];
        self.socket
            .read_exact(&mut c)
            .await
            .context(UnableToReadStatusByte)?;
        ensure!(b'+' == c[0], StatusByteNotSuccess { actual: c[0] });
        Ok(())
    }

    async fn respond_success(&mut self, response: &[u8]) -> io::Result<()> {
        use std::io::Write;

        let response_checksum = checksum_of(&response);
        let mut response_checksum_str = [0u8; 2];
        write!(&mut response_checksum_str[..], "{:02x}", response_checksum)
            .expect("Checksum buffer size mismatch");

        self.socket.write_all(b"+$").await?;
        self.socket.write_all(&response).await?;
        self.socket.write_all(b"#").await?;
        self.socket.write_all(&response_checksum_str).await?;
        self.socket.flush().await?;

        Ok(())
    }

    // next
    // "load"
    // X0,0:
    // -or- ?
    // M0,48e:
    // M48e,14:

    async fn handle_command(&mut self, body: &[u8]) -> Result<Vec<u8>> {
        match body {
            &[b'?', ref payload @ ..] => self.handle_halt_reason(payload).await,
            &[b'D', ref payload @ ..] => self.handle_detach(payload).await,
            &[b'H', ref payload @ ..] => self.handle_set_thread(payload).await,
            &[b'X', ref payload @ ..] => self.handle_set_memory_binary(payload).await,
            &[b'Z', ref payload @ ..] => self.handle_set_breakpoint(payload).await,
            &[b'g', ref payload @ ..] => self.handle_read_registers(payload).await,
            &[b'm', ref payload @ ..] => self.handle_get_memory(payload).await,
            &[b'q', ref payload @ ..] => self.handle_query(payload).await,
            &[b'v', ref payload @ ..] => self.handle_v(payload).await,
            &[b'z', ref payload @ ..] => self.handle_unset_breakpoint(payload).await,
            _ => UnknownCommand { body }.fail()?,
        }
    }

    async fn handle_halt_reason(&mut self, _body: &[u8]) -> Result<Vec<u8>> {
        Ok(b"T05swbreak:;".to_vec()) // add registers
    }

    async fn handle_detach(&mut self, _body: &[u8]) -> Result<Vec<u8>> {
        Ok(b"OK".to_vec())
    }

    async fn handle_set_thread(&mut self, body: &[u8]) -> Result<Vec<u8>> {
        // We don't have any threads, so nothing to track here
        match body {
            &[b'g', ref _thread_id @ ..] => Ok(b"OK".to_vec()),
            &[b'c', ref _thread_id @ ..] => Ok(b"OK".to_vec()), // Just make these silent?
            _ => UnknownSetThread { body }.fail(),
        }
    }

    async fn handle_set_memory_binary(&mut self, body: &[u8]) -> Result<Vec<u8>> {
        let (addr, tail) = split_at_char_or_end(body, b",");
        let (len, data) = split_at_char_or_end(tail, b":");

        let addr: u32 = dehex(addr).unwrap();
        let len: u32 = dehex(len).unwrap();

        dbg!(addr, len);

        Ok(b"".to_vec())
    }

    async fn handle_set_breakpoint(&mut self, body: &[u8]) -> Result<Vec<u8>> {
        match body {
            &[b'0', b',', ref payload @ ..] => self.handle_set_software_breakpoint(payload).await,
            _ => panic!("Unknown breakpoint {:?}", std::str::from_utf8(body)),
        }
    }

    async fn handle_unset_breakpoint(&mut self, body: &[u8]) -> Result<Vec<u8>> {
        match body {
            &[b'0', b',', ref payload @ ..] => self.handle_unset_software_breakpoint(payload).await,
            _ => panic!("Unknown breakpoint {:?}", std::str::from_utf8(body)),
        }
    }

    const BREAK_CODE: [u8; 2] = [0b1001_0101, 0b1001_1000];

    async fn handle_set_software_breakpoint(&mut self, body: &[u8]) -> Result<Vec<u8>> {
        let address = Self::parse_software_breakpoint(body)?;

        match self
            .ipc(Command::ReplaceCode, (address, Self::BREAK_CODE.to_vec()))
            .await?
        {
            Ok(original_code) => {
                self.active_breakpoints.insert(address, original_code);
                Ok(b"OK".to_vec())
            }
            Err(_e) => Ok(b"E01".to_vec()),
        }
    }

    async fn handle_unset_software_breakpoint(&mut self, body: &[u8]) -> Result<Vec<u8>> {
        let address = Self::parse_software_breakpoint(body)?;

        if let Some(original_code) = self.active_breakpoints.remove(&address) {
            match self
                .ipc(Command::ReplaceCode, (address, original_code))
                .await?
            {
                Ok(break_code) => {
                    assert_eq!(
                        Self::BREAK_CODE[..],
                        break_code[..],
                        "Unset something that didn't look like a breakpoint"
                    );
                    Ok(b"OK".to_vec())
                }
                Err(_e) => Ok(b"E01".to_vec()),
            }
        } else {
            Ok(b"OK".to_vec())
        }
    }

    fn parse_software_breakpoint(body: &[u8]) -> Result<u32> {
        let (address, len) = body.splitn(2, |&b| b == b',').next_tuple().unwrap();
        let address: u32 = dehex(address).unwrap();
        let len: u8 = dehex(len).unwrap();

        assert_eq!(len, 2u8, "Unknown breakpoint type");

        let address = address - 0x800000; // TODO: where's the right place to handle that?
        let address = address << 1; // It's using on the word-based PC.

        Ok(address)
    }

    async fn handle_read_registers(&mut self, _body: &[u8]) -> Result<Vec<u8>> {
        let registers = self.ipc(Command::GetRegisters, ()).await?;

        let mut result = [b'x'; 39 * 2];

        let r: io::Result<()> = try {
            use std::io::Write;

            let mut cursor = &mut result[..];

            for &register in &registers.r {
                write!(cursor, "{:02x}", register)?;
            }
            write!(cursor, "{:02x}", registers.status)?;
            write!(cursor, "{:04x}", registers.stack_pointer.to_be())?;
            write!(cursor, "{:08x}", registers.pc.to_be())?;
        };

        r.expect("Register buffer size mismatch");

        Ok(result.to_vec())
    }

    async fn handle_get_memory(&mut self, body: &[u8]) -> Result<Vec<u8>> {
        let (addr, len) = split_at_char_or_end(body, b",");
        let addr = dehex(addr).unwrap();
        let len: u16 = dehex(len).unwrap();

        match self.ipc(Command::GetMemory, addr..(addr + len)).await? {
            Ok(memory) => Ok(hex::encode(memory).into_bytes()),
            Err(_e) => Ok(b"E00".to_vec()), // better?
        }
    }

    async fn handle_query(&mut self, body: &[u8]) -> Result<Vec<u8>> {
        let (kind, _payload) = split_at_char_or_end(body, b":");

        match kind {
            b"C" => Ok(b"QCm1".to_vec()),     // current thread
            b"Attached" => Ok(b"1".to_vec()), // existing process
            b"Supported" => {
                //for thing in payload.split(|&b| b == b';') {
                //println!("{}", String::from_utf8_lossy(thing));
                //}
                Ok(b"PacketSize=1048576;multiprocess+;swbreak+;vContSupported+;".to_vec())
            }
            b"fThreadInfo" => Ok(b"m01".to_vec()), // only one thread
            b"sThreadInfo" => Ok(b"l".to_vec()),   // last
            _ => UnknownQuery { body }.fail(),
        }
    }

    async fn handle_v(&mut self, body: &[u8]) -> Result<Vec<u8>> {
        let (kind, payload) = split_at_char_or_end(body, b";");

        #[derive(Debug)]
        enum Kind {
            Continue,
            Step,
        }

        match kind {
            b"Cont" => {
                for action in payload.split(|&b| b == b';') {
                    let (cmd, thread_id) = match action {
                        &[b'c', b':', ref thread_id @ ..] => (Kind::Continue, thread_id),
                        &[b's', b':', ref thread_id @ ..] => (Kind::Step, thread_id),
                        _ => panic!("unknown"),
                    };

                    let thread_id = ThreadId::try_from(thread_id)?;

                    // We only care about one thread
                    if thread_id.is_primary() {
                        match cmd {
                            Kind::Continue => self.ipc(Command::Continue, ()).await?,
                            Kind::Step => self.command(Command::Step).await?
                        }
                    }
                }

                Ok(b"T05swbreak:;".to_vec()) // add registers; dedupe
            }
            b"Cont?" => Ok(b"cs".to_vec()), // todo: range; stop?
            _ => UnknownV { body }.fail(),
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum OneId {
    All,
    Arbitrary,
    Value(u16),
}

impl TryFrom<&[u8]> for OneId {
    type Error = Error;

    fn try_from(other: &[u8]) -> Result<Self> {
        use OneId::*;

        match other {
            b"0" => Ok(Arbitrary),
            b"-1" => Ok(All),
            other => dehex(other).map(Value).context(InvalidHexValue),
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
struct ThreadId {
    process: OneId,
    thread: OneId,
}

impl ThreadId {
    fn is_primary(&self) -> bool {
        self.thread == OneId::Value(1)
    }
}

impl TryFrom<&[u8]> for ThreadId {
    type Error = Error;

    fn try_from(other: &[u8]) -> Result<Self> {
        match other {
            [b'p', ref payload @ ..] => {
                let (process, thread) = match split_at_char_or_end(payload, b".") {
                    (pid, b"") => (pid.try_into()?, OneId::Arbitrary),
                    (pid, tid) => (pid.try_into()?, tid.try_into()?),
                };

                Ok(Self { process, thread })
            }
            _ => panic!(),
        }
    }
}

fn dehex<T>(hex: &[u8]) -> Result<T, hex::FromHexError>
where
    BigEndianInteger<T>: FromHex<Error = hex::FromHexError>,
{
    BigEndianInteger::<T>::from_hex(hex).map(|be| be.0)
}

struct BigEndianInteger<T>(T);

impl FromHex for BigEndianInteger<u8> {
    type Error = hex::FromHexError;

    fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, Self::Error> {
        let hex = hex.as_ref();

        // Leading zero padding
        let mut tmp = [b'0'; 2];
        for (d, s) in tmp.iter_mut().rev().zip(hex.iter().rev()) {
            *d = *s;
        }

        let bytes = <[u8; 1]>::from_hex(tmp)?;
        Ok(BigEndianInteger(u8::from_be_bytes(bytes)))
    }
}

impl FromHex for BigEndianInteger<u16> {
    type Error = hex::FromHexError;

    fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, Self::Error> {
        let hex = hex.as_ref();

        // Leading zero padding
        let mut tmp = [b'0'; 4];
        for (d, s) in tmp.iter_mut().rev().zip(hex.iter().rev()) {
            *d = *s;
        }

        let bytes = <[u8; 2]>::from_hex(tmp)?;
        Ok(BigEndianInteger(u16::from_be_bytes(bytes)))
    }
}

impl FromHex for BigEndianInteger<u32> {
    type Error = hex::FromHexError;

    fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, Self::Error> {
        let hex = hex.as_ref();

        // Leading zero padding
        let mut tmp = [b'0'; 8];
        for (d, s) in tmp.iter_mut().rev().zip(hex.iter().rev()) {
            *d = *s;
        }

        let bytes = <[u8; 4]>::from_hex(tmp)?;
        Ok(BigEndianInteger(u32::from_be_bytes(bytes)))
    }
}

fn checksum_of(bytes: &[u8]) -> u8 {
    bytes.iter().copied().fold(0, u8::wrapping_add)
}

fn split_at_char_or_end<'a>(bytes: &'a [u8], chars: &[u8]) -> (&'a [u8], &'a [u8]) {
    match bytes.iter().position(|b| chars.contains(b)) {
        Some(position) => {
            let (head, tail) = bytes.split_at(position);
            let (_, tail) = tail.split_at(1); // Skip the matched character
            (head, tail)
        }
        None => {
            let position = bytes.len();
            bytes.split_at(position)
        }
    }
}

#[derive(Debug, Snafu)]
pub enum Error {
    UnableToBind {
        source: io::Error,
    },

    UnableToAccept {
        source: io::Error,
    },

    UnableToReadStatusByte {
        source: io::Error,
    },

    #[snafu(display("Packet was not success {:02x} ({})", actual, *actual as char))]
    StatusByteNotSuccess {
        actual: u8,
    },

    UnableToReadPacket {
        source: io::Error,
    },

    UnableToReadChecksum {
        source: io::Error,
    },

    #[snafu(display(
            "Packet has wrong encapsulation 0x{:02x}/0x{:02x} ('{}'/'{}')",
            head, tail, *head as char, *tail as char,
        ))]
    PacketHasWrongEncapsulation {
        head: u8,
        tail: u8,
    },

    PacketTooShort {
        len: usize,
    },

    ChecksumNotHex {
        source: hex::FromHexError,
    },

    ChecksumFailed {
        actual: u8,
        expected: u8,
    },

    UnableToSendResponse {
        source: io::Error,
    },

    // -----
    #[snafu(display("Unknown command: {}", String::from_utf8_lossy(body)))]
    UnknownCommand {
        body: Vec<u8>,
    },

    #[snafu(display("Unknown set thread: {}", String::from_utf8_lossy(body)))]
    UnknownSetThread {
        body: Vec<u8>,
    },

    #[snafu(display("Unknown query: {}", String::from_utf8_lossy(body)))]
    UnknownQuery {
        body: Vec<u8>,
    },

    #[snafu(display("Unknown v: {}", String::from_utf8_lossy(body)))]
    UnknownV {
        body: Vec<u8>,
    },

    // -----
    InvalidHexValue {
        source: hex::FromHexError,
    },
}

pub(crate) type Result<T, E = Error> = std::result::Result<T, E>;
