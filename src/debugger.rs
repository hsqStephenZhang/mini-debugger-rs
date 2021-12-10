use std::{
    collections::HashMap,
    fs::File,
    io::{self, BufRead},
};

use libc::{pid_t, ptrace, siginfo_t};
use nix::{errno::Errno, unistd::Pid};
use rustyline::{error::ReadlineError, Editor};

use crate::{
    breakpoint::BreakPoint,
    command::{Gdb, Info, Memory},
    utils::{str_to_u64, str_to_usize},
};

pub const TRAP_BRKPT: i32 = 1; /* process breakpoint */
pub const TRAP_TRACE: i32 = 2; /* process trace trap */
pub const TRAP_BRANCH: i32 = 3; /* process taken branch trap */
pub const TRAP_HWBKPT: i32 = 4; /* hardware breakpoint/watchpoint */
pub const TRAP_UNK: i32 = 5; /* undiagnosed trap */
pub const TRAP_PERF: i32 = 6; /* perf event with sigtrap=1 */
pub const SI_KERNEL: i32 = 0x80; /* kernel signal */

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
    pub breakpoints: HashMap<u64, BreakPoint>,
    pub index_to_breakpoints: HashMap<usize, u64>,
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

    pub fn set_state(&mut self, state: State) {
        let s = &mut self.state;
        *s = state;
    }

    pub fn initialize_load_addr(&mut self) {
        let proc_maps = format!("/proc/{}/maps", self.prog_pid);
        let file = File::open(proc_maps).unwrap();
        let mut iter = io::BufReader::new(file).lines();
        let first_line = iter.next().unwrap().unwrap();
        let items = first_line.splitn(2, '-').collect::<Vec<_>>();
        let base_addr = items[0];
        let addr = usize::from_str_radix(base_addr, 16).unwrap();
        self.load_addr = addr;
        println!("load addr:{:x?}", self.load_addr);
    }

    pub fn set_breakpointer_at_address(&mut self, addr: u64) {
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

    pub fn dump_registers(&self) {
        let registers = self.get_registers();
        println!("registers:\n{:?}", registers);
    }

    pub fn dump_register(&self, name: &str) {
        let mut registers = self.get_registers();
        let register = self.name_to_register(&mut registers, name);
        match register {
            Some(r) => {
                println!("{} : {:x}", name, r);
            }
            None => println!("register name not found:{}", name),
        }
    }

    pub fn set_register(&self, name: &str, value: u64) {
        let mut registers = self.get_registers();
        match self.name_to_register(&mut registers, name) {
            Some(r) => {
                *r = value;
                self.set_registers(registers);
            }
            None => {
                println!("register name not found:{}", name);
            }
        }
    }

    pub fn set_registers(&self, mut registers: libc::user_regs_struct) {
        let p = &mut registers as *mut _ as *mut libc::c_void;
        unsafe {
            ptrace(libc::PTRACE_SETREGS, self.prog_pid, 0, p);
        }
    }

    pub fn get_pc(&self) -> u64 {
        self.get_registers().rip
    }

    pub fn set_pc(&self, pc: u64) {
        let mut registers = self.get_registers();
        registers.rip = pc;
        self.set_registers(registers);
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

    pub fn single_step_instruction(&mut self) {
        unsafe {
            ptrace(libc::PTRACE_SINGLESTEP, self.prog_pid, 0, 0);
            self.wait_for_signal();
        }
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

    // if there is a breakpoint at this point, we will:
    //      1. disable the breakpoint, restore the instruction
    //      2. ptrace single step, execute this instruction, after it, will trigger sigtrap
    //      3. waitpid, handle the sigtrap
    //      4. enable the breakpoint
    pub fn step_over_breakpoint(&mut self) {
        let registers = self.get_registers();
        let breakpoint_addr = registers.rip;
        dbg!(&registers, &self.breakpoints);
        let breakpoint = self.breakpoints.get_mut(&breakpoint_addr);
        match breakpoint {
            Some(b) => {
                println!("step over breakpoint, breakpoint:{:?}", b);
                let ptr = b as *mut BreakPoint;
                if b.enabled {
                    b.disable();
                    unsafe {
                        ptrace(libc::PTRACE_SINGLESTEP, self.prog_pid, 0, 0);
                        self.wait_for_signal();
                        // SAFETY: it' under control
                        (*(&mut *ptr)).enable();
                    }
                }
            }
            None => {
                println!("no breakpoint here, just execute until next breakpoint");
            }
        }
    }

    pub fn continue_exec(&mut self) -> Result<(), Errno> {
        // ptrace continue can let the tracee continue to run
        unsafe {
            self.step_over_breakpoint();
            libc::ptrace(libc::PTRACE_CONT, self.prog_pid, 0, 0);
            self.wait_for_signal()?;
            return Ok(());
        }
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
                Gdb::Continue => {
                    self.handle_continue();
                }
                Gdb::Break { addr } => {
                    self.handle_breakpoint(addr);
                }
                Gdb::Info { info } => self.handle_info(info),
                Gdb::Quit => self.handle_quit(),
                Gdb::Enable { index } => self.handle_enable(index),
                Gdb::Disable { index } => self.handle_disable(index),
                Gdb::Memory { memory } => self.handle_memory(memory),
                Gdb::Stepi => self.single_step_instruction(),
                _ => {}
            },
            Err(e) => {
                println!("error:{:}", e);
            }
        }
    }

    pub fn handle_continue(&mut self) {
        if let Err(err) = self.continue_exec() {
            match err {
                Errno::ESRCH => {
                    println!("process dead: {}", self.prog_pid);
                    self.set_state(State::Closed);
                }
                _ => {}
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
        let addr = str_to_u64(&addr);
        match addr {
            Ok(addr) => {
                self.set_breakpointer_at_address(addr);
            }
            Err(er) => println!("unknown type of address: {:?}", addr),
        }
    }

    pub fn handle_enable(&mut self, index: usize) {
        if let Some(addr) = self.index_to_breakpoints.get(&index) {
            let breakpoint = self.breakpoints.get_mut(addr).unwrap();
            breakpoint.enable();
        } else {
            println!("no breakpoint of index {:?}", index);
        }
    }

    pub fn handle_disable(&mut self, index: usize) {
        if let Some(addr) = self.index_to_breakpoints.get(&index) {
            let breakpoint = self.breakpoints.get_mut(addr).unwrap();
            breakpoint.disable();
        } else {
            println!("no breakpoint of index {:?}", index);
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

    // when we hit a breakpoint, the instruction and pc display like:
    //     
    // original instruction:
    //         55          push %rbp
    //         48 89 e5    mov  %rsp,%rbp 
    //
    // hooked instruction:
    //         cc          int3
    // pc->    48 89 e5    mov  %rsp,%rbp     

    // we now set the pc to:
    // pc->    cc          int3
    //         48 89 e5    mov  %rsp,%rbp 
    pub fn handle_sigtrap(&mut self, info: siginfo_t) {
        let registers = dbg!(self.get_registers());
        match info.si_code {
            TRAP_BRKPT | SI_KERNEL => {
                let current_pc = registers.rip;
                self.set_pc(current_pc - 1);
                println!("Hit breakpoint at address: {:?}", current_pc);
            }
            TRAP_TRACE => {}
            _ => {
                println!("unimplemented of sigtrap code: {:?}", info);
            }
        }
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
    pub fn wait_for_signal(&mut self) -> Result<(), Errno> {
        unsafe {
            self.wait_signal_info();
            let info = self.get_signal_info()?;

            match info.si_signo {
                libc::SIGTRAP => {
                    self.handle_sigtrap(info);
                }
                libc::SIGSEGV => {
                    println!("catch segfault. Reason: {:?}", info);
                }
                _ => {
                    println!("get signal {:?}", info);
                }
            }

            return Ok(());
        }
    }

    pub fn get_signal_info(&self) -> Result<siginfo_t, Errno> {
        let pid = Pid::from_raw(self.prog_pid);
        nix::sys::ptrace::getsiginfo(pid)
    }

    pub fn wait_signal_info(&self) -> i32 {
        let mut wait_status = 0;
        let option = 0;
        unsafe { libc::waitpid(self.prog_pid, &mut wait_status as _, option) }
    }

    #[cfg(not(mock))]
    pub fn run(&mut self) {
        let state = &mut self.state;
        *state = State::Running;
        self.initialize_load_addr();
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

    #[cfg(mock)]
    pub fn run(&mut self) {
        todo!();
    }
}

fn tokens(input: &str) -> Vec<&str> {
    input
        .split(" ")
        .map(|s| s.trim().trim_end())
        .filter(|&v| v != "")
        .collect()
}
