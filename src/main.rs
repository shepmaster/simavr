#![deny(rust_2018_idioms)]
#![feature(try_blocks)]

use futures::{
    channel::{mpsc, oneshot},
    StreamExt,
};
use snafu::{ResultExt, Snafu};
use std::{fmt, ops};
use tokio::task;

mod gdb;
mod machine;

use machine::{Machine, Registers, Status};

#[tokio::main]
async fn main() -> Result<()> {
    let (command_tx, command_rx) = mpsc::channel(10);
    let machine = Machine::default();

    let emulate_task = task::spawn(async {
        eprintln!("Emulation starting...");
        let r = emulate(machine, command_rx).await;
        eprintln!("Emulation complete");
        r
    });

    let _input_task = task::spawn(async {
        eprintln!("Input starting...");
        let r = listen_to_user(command_tx).await;
        eprintln!("Input complete");
        if let Err(e) = &r {
            eprintln!("{}\n{:?}", e, e);
        }
        r
    });

    let r = emulate_task.await;

    match r {
        Ok(Ok(())) => eprintln!("Successful"),
        Ok(Err(e)) => eprintln!("Error: {}\n{:?}", e, e),
        Err(_) => eprintln!("Task panicked"),
    }

    Ok(())
}

struct Ipc<A, R> {
    args: A,
    resp: oneshot::Sender<R>,
}

impl<A, R> Ipc<A, R> {
    fn new(args: A) -> (Self, oneshot::Receiver<R>) {
        let (resp, rx) = oneshot::channel();
        let me = Self { args, resp };
        (me, rx)
    }
}

impl<A, R> fmt::Debug for Ipc<A, R>
where
    A: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Ipc({:?} -> {}", self.args, std::any::type_name::<R>())
    }
}

#[derive(Debug)]
pub(crate) enum Command {
    Continue (Ipc<(), ()>),
    Halt,
    GetRegisters(Ipc<(), Registers>),
    GetMemory(Ipc<ops::Range<u16>, machine::Result<Vec<u8>>>),
    ReplaceCode(Ipc<(u32, Vec<u8>), machine::Result<Vec<u8>>>),
    Step,
}

async fn emulate(mut machine: Machine, mut command_rx: mpsc::Receiver<Command>) -> Result<()> {
    let mut halted = false;
    let mut notify_of_halt: Option<oneshot::Sender<()>> = None;

    loop {
        let command = futures::select! {
            command = command_rx.next() => command,
            default => {
                if halted {
                    command_rx.next().await
                } else {
                    // Continue emulation if no commands to handle and not halted
                    if Status::Breakpoint == machine.step().context(MachineExecutionFailed)? {
                        halted = true;
                        if let Some(notify_of_halt) = notify_of_halt.take() {
                            notify_of_halt.send(()).unwrap();
                        }
                    }

                    #[allow(deprecated)]
                    std::thread::sleep_ms(500);

                    continue;
                }
            }
        };

        let command = match command {
            Some(command) => command,
            None => return Ok(()),
        };

        eprintln!("Processing command: {:?}", command);

        use Command::*;
        match command {
            ReplaceCode(Ipc {
                args: (addr, code),
                resp,
            }) => resp.send(machine.replace_code(addr, &code)).unwrap(),
            Continue(Ipc { resp, .. }) => {
                notify_of_halt = Some(resp);
                halted = false;
            },
            GetRegisters(Ipc { resp, .. }) => resp.send(machine.registers()).unwrap(),
            GetMemory(Ipc { args, resp }) => {
                resp.send(machine.memory(args).map(|s| s.to_vec())).unwrap()
            }
            Halt => halted = true,
            Step => {
                if Status::Breakpoint == machine.step().context(MachineExecutionFailed)? {
                    halted = true;
                    if let Some(notify_of_halt) = notify_of_halt.take() {
                        notify_of_halt.send(()).unwrap();
                    }
                }
            }
        }
    }
}

async fn listen_to_user(command_tx: mpsc::Sender<Command>) -> Result<()> {
    let gdb = task::spawn(gdb::listen(command_tx));

    gdb.await.context(GdbTaskPanicked)?.context(GdbTaskFailed)
}

#[derive(Debug, Snafu)]
enum Error {
    MachineExecutionFailed { source: machine::Error },

    GdbTaskPanicked { source: task::JoinError },
    GdbTaskFailed { source: gdb::Error },
}

type Result<T, E = Error> = std::result::Result<T, E>;
