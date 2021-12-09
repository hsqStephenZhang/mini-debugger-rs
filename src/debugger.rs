use std::collections::HashMap;

use libc::{pid_t, ptrace};
use rustyline::{error::ReadlineError, Editor};

use crate::{
    breakpoint::BreakPoint,
    command::{Gdb, Info, Memory},
    utils::str_to_usize,
};

#[derive(Clone, Debug)]
pub enum State {
    NotRunning,
    Running,
    Closed,
}

#[derive(Debug, Clone)]
pub enum Symbol {
    None,
    Object,
    Func,
    Section,
    File,
}

pub struct Debugger {
    pub state: State,
    pub prog_name: String,
    pub prog_pid: pid_t,
    pub load_addr: usize,
    pub breakpoints: HashMap<usize, BreakPoint>,
    pub index_to_breakpoints: HashMap<usize, usize>,
    pub next_breakpoint_index: usize,
}

#[allow(warnings)]
impl Debugger {
    // TODO: read the proc file, set the load addr
    pub fn new(prog_name: String, prog_pid: pid_t) -> Self {
        Self {
            state: State::NotRunning,
            prog_name,
            prog_pid,
            load_addr: 0,
            breakpoints: HashMap::new(),
            index_to_breakpoints: HashMap::new(),
            next_breakpoint_index: 0,
        }
    }

    pub fn set_breakpointer_at_address(&mut self, addr: usize) {
        let mut breakpoint = BreakPoint::new(self.prog_pid, addr);
        breakpoint.enable();
        self.breakpoints.insert(addr, breakpoint);
        let index = self.next_breakpoint_index;
        self.index_to_breakpoints.insert(index, addr);
        self.next_breakpoint_index += 1;
    }

    pub fn set_breakpointer_at_function(&mut self, addr: usize) {
        todo!()
    }

    pub fn set_breakpointer_at_source_line(&mut self, addr: usize) {
        todo!()
    }

    pub fn dump_breakpoints(&self) {
        for (index, addr) in self.index_to_breakpoints.iter() {
            let breakpoint = &self.breakpoints[addr];
            println!("{:<5}: {:?}", index, breakpoint);
        }
    }

    pub fn get_registers(&self) -> libc::user_regs_struct {
        unsafe {
            let mut registers: libc::user_regs_struct =
                std::mem::MaybeUninit::uninit().assume_init();
            let p = &mut registers as *mut _ as *mut libc::c_void;
            ptrace(libc::PTRACE_GETREGS, self.prog_pid, 0, p);
            registers
        }
    }

    pub fn dump_registers(&self) {
        let registers = self.get_registers();
        println!("registers:\n{:?}", registers);
    }

    pub fn name_to_register<'a>(
        &self,
        registers: &'a mut libc::user_regs_struct,
        name: &str,
    ) -> Option<&'a mut libc::c_ulonglong> {
        return match name {
            "r15" => Some(&mut registers.r14),
            "r14" => Some(&mut registers.r13),
            "r13" => Some(&mut registers.r12),
            "r12" => Some(&mut registers.r11),
            "rbp" | "ebp" => Some(&mut registers.rbp),
            "rbx" | "ebx" => Some(&mut registers.rbx),
            "r11" => Some(&mut registers.r11),
            "r10" => Some(&mut registers.r10),
            "r9" => Some(&mut registers.r9),
            "r8" => Some(&mut registers.r8),
            "rax" | "eax" => Some(&mut registers.rax),
            "rcx" | "ecx" => Some(&mut registers.rcx),
            "rdx" | "edx" => Some(&mut registers.rdx),
            "rsi" | "esi" => Some(&mut registers.rsi),
            "rdi" | "edi" => Some(&mut registers.rdi),
            "orig_rax" => Some(&mut registers.orig_rax),
            "rip" | "pc" => Some(&mut registers.rip),
            "cs" => Some(&mut registers.cs),
            "eflags" => Some(&mut registers.eflags),
            "rsp" | "esp" => Some(&mut registers.rsp),
            "ss" => Some(&mut registers.ss),
            "fs_base" => Some(&mut registers.fs_base),
            "gs_base" => Some(&mut registers.gs_base),
            "ds" => Some(&mut registers.ds),
            "es" => Some(&mut registers.es),
            "fs" => Some(&mut registers.fs),
            "gs" => Some(&mut registers.gs),
            _ => None,
        };
    }

    pub fn dump_register(&self, name: &str) {
        let mut registers = self.get_registers();
        let register = self.name_to_register(&mut registers, name);
        match register {
            Some(r) => {
                println!("register name: {}, register value{:x}", name, r);
            }
            None => println!("register name not found:{}", name),
        }
    }

    pub fn print_backtrace(&self) {
        todo!()
    }

    pub fn print_source(&self) {
        todo!()
    }

    pub fn lookup_symbol(&self) {
        todo!()
    }

    // ====== debug related functions

    pub fn single_step_instructions(&mut self) {
        todo!()
    }

    pub fn single_step_instructions_with_breakpoint_check(&mut self) {
        todo!()
    }

    pub fn step_in(&mut self) {
        todo!()
    }

    pub fn step_out(&mut self) {
        todo!()
    }

    pub fn step_over(&mut self) {
        todo!()
    }

    pub fn continue_exec(&mut self) {
        // ptrace continue can let the tracee continue to run
        unsafe {
            libc::ptrace(libc::PTRACE_CONT, self.prog_pid, 0, 0);

            let mut wait_status = 0;
            let option = 0;
            libc::waitpid(self.prog_pid, &mut wait_status as _, option);
            dbg!(wait_status);
        }
    }

    pub fn get_pc(&self) {
        todo!()
    }

    pub fn set_pc(&self, pc: usize) {
        todo!()
    }

    pub fn step_over_breakpoint(&self) {
        todo!()
    }

    pub fn handle_command(&mut self, comm: &str) {
        let parts = tokens(comm);
        if parts.len() == 0 {
            // skip null command
            return;
        }
        let parsed = super::command::into_gdb(parts);

        match parsed {
            Ok(gdb) => match gdb {
                Gdb::Continue => self.continue_exec(),
                Gdb::Break { addr } => {
                    self.handle_breakpoint(addr);
                }
                Gdb::Info { info } => self.handle_info(info),
                Gdb::Quit => self.handle_quit(),
                Gdb::Memory { memory } => self.handle_memory(memory),
                _ => {}
            },
            Err(e) => {
                println!("error:{:}", e);
            }
        }
    }

    pub fn handle_quit(&mut self) {
        match self.state {
            State::Running => {
                println!("debugger is running, do you want to close is?(yes for close, other for cancel)");
                let mut buffer = String::new();
                let r = std::io::stdin().read_line(&mut buffer).unwrap();
                let content = buffer.trim().trim_end();
                match content.to_lowercase().as_str() {
                    "yes" | "y" => {
                        let mut state = &mut self.state;
                        *state = State::Closed;
                    }
                    _ => {}
                }
            }
            _ => {
                let mut state = &mut self.state;
                *state = State::Closed;
            }
        }
    }

    pub fn handle_breakpoint(&mut self, addr: String) {
        let addr = str_to_usize(&addr);
        match addr {
            Ok(addr) => {
                self.set_breakpointer_at_address(addr);
            }
            Err(er) => println!("unknown type of address: {:?}", addr),
        }
    }

    pub fn handle_info(&self, info: Info) {
        match info {
            crate::command::Info::Breakpoints => self.dump_breakpoints(),
            crate::command::Info::Registers => self.dump_registers(),
            crate::command::Info::Register { name } => {
                if let Some(name) = name {
                    self.dump_register(&name);
                }
            }
        }
    }

    pub fn handle_memory(&mut self, memory: Memory) {
        match memory {
            Memory::Read { addr } => {
                let addr = str_to_usize(&addr);
                match addr {
                    Ok(addr) => {
                        let data = self.read_memory(addr);
                        let data: [u8; 8] = unsafe { std::mem::transmute(data) };
                        println!("read {:x?}", data);
                    }
                    Err(er) => println!("read memory failed, unknown address: {:?}", addr),
                }
            }
            Memory::Write { addr, value } => {
                let addr = str_to_usize(&addr);
                let addr = match addr {
                    Ok(addr) => addr,
                    Err(er) => {
                        println!("read memory failed, unknown address: {:?}", addr);
                        return;
                    }
                };

                let value = str_to_usize(&value);
                match value {
                    Ok(value) => {
                        self.write_memory(addr, value);
                        println!("write {:?}:{:?}", addr, value);
                    }
                    Err(er) => println!("read memory failed, unknown address: {:?}", addr),
                }
            }
        }
    }

    pub fn handle_sigtrap(&mut self) {
        todo!()
    }

    // ====== memory
    pub fn read_memory(&self, addr: usize) -> i64 {
        unsafe {
            let data = libc::ptrace(libc::PTRACE_PEEKDATA, self.prog_pid, addr, 0);
            data
        }
    }

    pub fn write_memory(&mut self, addr: usize, value: usize) {
        unsafe {
            libc::ptrace(libc::PTRACE_POKEDATA, self.prog_pid, addr, value);
        }
    }

    // signal handle at the very beginning
    pub fn wait_for_signal(&mut self) {
        unsafe {
            let mut wait_status = 0;
            let option = 0;
            libc::waitpid(self.prog_pid, &mut wait_status as _, option);
            dbg!(wait_status);

            let mut info = 0;
            libc::ptrace(
                libc::PTRACE_GETSIGINFO,
                self.prog_pid,
                0,
                &mut info as *mut _ as *mut libc::c_void,
            );

            match info {
                libc::SIGSEGV => {
                    self.handle_sigtrap();
                }
                libc::SIGTRAP => {
                    println!("catch segfault. Reason: {}", info);
                }
                _ => {
                    println!("get signal {}", info);
                }
            }
        }
    }

    pub fn run(&mut self) {
        let state = &mut self.state;
        *state = State::Running;
        let mut rl = Editor::<()>::new();
        if rl.load_history(".gdbrs.history").is_err() {
            println!("No previous history.");
        }
        loop {
            match self.state {
                State::Closed => {
                    println!("debugger closed");
                    return;
                }
                _ => {}
            }
            let readline = rl.readline("minidbg>> ");
            match readline {
                Ok(line) => {
                    rl.add_history_entry(line.as_str());
                    self.handle_command(&line);
                }
                Err(ReadlineError::Interrupted) => {
                    println!("CTRL-C");
                    break;
                }
                Err(ReadlineError::Eof) => {
                    println!("CTRL-D");
                    break;
                }
                Err(err) => {
                    println!("Error: {:?}", err);
                    break;
                }
            }
        }
        rl.save_history(".gdbrs.history").unwrap();
    }
}

fn tokens(input: &str) -> Vec<&str> {
    input
        .split(" ")
        .map(|s| s.trim().trim_end())
        .filter(|&v| v != "")
        .collect()
}
