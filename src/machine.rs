use snafu::{OptionExt, Snafu};
use std::{fmt, ops};

#[derive(Debug, Copy, Clone, Default)]
pub(crate) struct Registers {
    pub(crate) pc: u32,
    pub(crate) r: [u8; 32],
    pub(crate) status: u8,
    pub(crate) stack_pointer: u16,
}

pub(crate) struct Machine {
    registers: Registers,
    memory: Vec<u8>, // TODO: array?
    code: Vec<u8>,   // TODO: array?
}

impl Default for Machine {
    fn default() -> Self {
        Self {
            registers: Default::default(),
            memory: vec![0; 8096], // TODO: actual sizes
            code: vec![0; 8096],   // TODO: actual sizes
        }
    }
}

impl fmt::Debug for Machine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Machine")
            .field("registers", &self.registers)
            .field("memory", &"<...>")
            .field("code", &"<...>")
            .finish()
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) enum Status {
    Normal,
    Breakpoint,
}

impl Machine {
    pub(crate) fn registers(&self) -> Registers {
        self.registers
    }

    pub(crate) fn memory(&self, range: ops::Range<u16>) -> Result<&[u8]> {
        let start = usize::from(range.start);
        let end = usize::from(range.end);
        self.memory
            .get(start..end)
            .context(MemoryCaptureOutOfBounds {
                start: range.start,
                end: range.end,
            })
    }

    fn opcode(&self) -> Option<u16> {
        let effective_pc: usize = u32_to_usize(self.registers.pc) << 1;
        let o0 = *self.code.get(effective_pc)?;
        let o1 = *self.code.get(effective_pc + 1)?;

        Some(u16::from(o0) << 8 | u16::from(o1))
    }

    pub(crate) fn step(&mut self) -> Result<Status> {
        let opcode = self.opcode().context(ProgramCounterOutOfBounds {
            pc: self.registers.pc,
        })?;

        let op = Instruction::decode(opcode)?;

        let update = op.execute();

        self.registers.pc += 1;

        let pc_delta = i32::from(update.pc_delta);
        match (pc_delta.is_negative(), pc_delta.abs() as u32) {
            (true, delta) => self.registers.pc = u32::checked_sub(self.registers.pc, delta).unwrap(),
            (_, delta) => self.registers.pc = u32::checked_add(self.registers.pc, delta).unwrap(),
        }

        // Hacks, yo
        if self.registers.pc == 2 {
            self.registers.pc = 0;
        }

        if update.breakpoint {
            Ok(Status::Breakpoint)
        } else {
            Ok(Status::Normal)
        }
    }

    /// Address is byte-based
    pub(crate) fn replace_code(&mut self, address: u32, code: &[u8]) -> Result<Vec<u8>> {
        let u_address = u32_to_usize(address);

        let target = self
            .code
            .get_mut(u_address..u_address + code.len())
            .context(BreakpointOutOfBounds {
                address,
                len: code.len(),
            })?;

        let old = target.to_vec();
        target.copy_from_slice(code);

        Ok(old)
    }
}

#[cfg(any(target_pointer_width = "32", target_pointer_width = "64"))]
fn u32_to_usize(v: u32) -> usize {
    v as usize
}

// NOP   0000_0000_0000_0000 cycles:1
// RJMP  1100_kkkk_kkkk_kkkk k:i16 cycles:2
// BREAK 1001_0101_1001_1000 cycles:1
#[derive(Debug, Copy, Clone)]
enum Instruction {
    Nop,
    Rjmp { k: i16 },
    Break,
}

impl Instruction {
    #[allow(dead_code)]
    fn mnemonic(&self) -> &'static str {
        use Instruction::*;
        match self {
            Nop => "NOP",
            Rjmp { .. } => "RJMP",
            Break => "BREAK",
        }
    }

    fn decode(opcode: u16) -> Result<Self> {
        if opcode == 0 {
            return Ok(Self::Nop);
        }

        // 1100 kkkk kkkk kkkk
        let masked = opcode & 0b1111_0000_0000_000;
        if masked == 0b1100_0000_0000_0000 {
            let k = opcode & 0b0000_1111_1111_1111;
            let k = k as i16;
            return Ok(Self::Rjmp { k });
        }

        // 1001_0101_1001_1000
        if opcode == 0b1001_0101_1001_1000 {
            return Ok(Self::Break);
        }

        InvalidOpcode { opcode }.fail()
    }

    fn execute(self) -> Update {
        use Instruction::*;
        match self {
            Nop => Update::default(),
            Rjmp { k } => Update {
                pc_delta: k,
                ..Update::default()
            },
            Break => Update {
                breakpoint: true,
                ..Update::default()
            }
        }
    }
}

#[derive(Debug, Copy, Clone, Default)]
struct Update {
    breakpoint: bool,
    pc_delta: i16,
}

#[derive(Debug, Snafu)]
pub(crate) enum Error {
    ProgramCounterOutOfBounds { pc: u32 },
    #[snafu(display("Invalid opcode ({0} / 0x{0:04x} / 0b{0:016b})", opcode))]
    InvalidOpcode { opcode: u32 },
    MemoryCaptureOutOfBounds { start: u16, end: u16 },
    BreakpointOutOfBounds { address: u32, len: usize },
}

pub(crate) type Result<T, E = Error> = std::result::Result<T, E>;
