use std::{
    collections::HashMap,
    fs::File,
    io::{self, BufRead},
    rc::Rc,
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

pub struct Debugger<'a> {
    pub state: State,
    pub prog_name: String,
    pub prog_pid: pid_t,
    pub load_addr: usize,
    pub breakpoints: HashMap<u64, BreakPoint>,
    pub index_to_breakpoints: HashMap<usize, u64>,
    pub next_breakpoint_index: usize,
    pub obj_file: object::File<'a>,
}

#[allow(warnings)]
impl<'a> Debugger<'a> {
    pub fn new(prog_name: String, prog_pid: pid_t, ojb_file: object::File<'a>) -> Self {
        Self {
            state: State::NotRunning,
            prog_name,
            prog_pid,
            load_addr: 0,
            breakpoints: HashMap::new(),
            index_to_breakpoints: HashMap::new(),
            next_breakpoint_index: 0,
            obj_file: ojb_file,
        }
    }

    pub fn set_state(&mut self, state: State) {
        let s = &mut self.state;
        *s = state;
    }

    fn offset_loadaddr(&self, cur: u64) -> u64 {
        cur - self.load_addr as u64
    }

    pub fn print_source(&self, location: &addr2line::Location, num_lines: usize) {
        if let (Some(filename), Some(line_idx)) = (location.file, location.line) {
            info!("reading source file:{:?}, line: {:?}", filename, line_idx);
            match crate::utils::read_lines(filename) {
                Ok(lines) => {
                    for (idx, line) in lines
                        .into_iter()
                        .enumerate()
                        .skip(line_idx as usize - 1)
                        .take(num_lines)
                    {
                        println!("{}: {}", idx, line.unwrap());
                    }
                }
                Err(e) => println!("read source file err: {:?}", e),
            }
        } else {
            warn!("source file content not found");
        }
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
        info!("load addr: 0x{:x?}", self.load_addr);
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

    pub fn name_to_register<'b>(
        &self,
        registers: &'b mut libc::user_regs_struct,
        name: &str,
    ) -> Option<&'b mut libc::c_ulonglong> {
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

    pub fn set_registers(&self, mut registers: libc::user_regs_struct) {
        let p = &mut registers as *mut _ as *mut libc::c_void;
        unsafe {
            ptrace(libc::PTRACE_SETREGS, self.prog_pid, 0, p);
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

    pub fn get_pc(&self) -> u64 {
        self.get_registers().rip
    }

    pub fn set_pc(&self, pc: u64) {
        let mut registers = self.get_registers();
        registers.rip = pc;
        self.set_registers(registers);
    }

    // ====== debug related functions

    pub fn single_step_instruction(&mut self) {
        unsafe {
            ptrace(libc::PTRACE_SINGLESTEP, self.prog_pid, 0, 0);
            self.wait_for_signal();
        }
    }

    pub fn single_step_instruction_with_breakpoint_check(&mut self) {
        let pc = self.get_pc();
        if let Some(v) = self.breakpoints.get(&pc) {
            self.step_over_breakpoint();
        } else {
            self.single_step_instruction();
        }
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
        // dbg!(&registers, &self.breakpoints);
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
                Gdb::Backtrace => {
                    self.handle_backtrace();
                }
                Gdb::Break { addr } => {
                    self.handle_breakpoint(addr);
                }
                Gdb::Continue => {
                    self.handle_continue();
                }
                Gdb::Enable { index } => self.handle_enable(index),
                Gdb::Disable { index } => self.handle_disable(index),
                Gdb::Disassemble { addr } => self.handle_disassemble(addr),
                Gdb::Info { info } => self.handle_info(info),
                Gdb::Memory { memory } => self.handle_memory(memory),
                Gdb::Quit => self.handle_quit(),
                Gdb::Stepi => self.single_step_instruction_with_breakpoint_check(),
                _ => {}
            },
            Err(e) => {
                println!("error:{:}", e);
            }
        }
    }

    pub fn handle_backtrace(&self) {
        let mut frame_number = 0;

        let mut frame_dumper = |func_name: addr2line::FunctionName<
            gimli::EndianReader<gimli::RunTimeEndian, Rc<[u8]>>,
        >,
                                func_location: addr2line::Location| {
            frame_number += 1;

            println!(
                "frame #{}, {:?} at {} line {}",
                frame_number,
                func_name.raw_name().unwrap(),
                func_location.file.unwrap_or(""),
                func_location.line.unwrap_or(0)
            );
        };

        let pc = self.offset_loadaddr(self.get_pc());
        let ctx = addr2line::Context::new(&self.obj_file).unwrap();
        let res = ctx.find_frames(pc);
        let unit = ctx.find_dwarf_unit(pc).unwrap();
        match res {
            Ok(mut frame_iter) => {
                while let Ok(Some(f)) = frame_iter.next() {
                    let func_name = f.function;
                    let func_location = f.location;
                    if let (Some(func_name), Some(func_location)) = (func_name, func_location) {
                        frame_dumper(func_name, func_location);
                    }
                }
            }
            err => {
                warn!("no backtrace at this position, pc={}", pc);
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

    pub fn handle_disable(&mut self, index: usize) {
        if let Some(addr) = self.index_to_breakpoints.get(&index) {
            let breakpoint = self.breakpoints.get_mut(addr).unwrap();
            breakpoint.disable();
        } else {
            println!("no breakpoint of index {:?}", index);
        }
    }

    // TODO: use addr
    pub fn handle_disassemble(&mut self, addr: Option<String>) {
        let ctx = addr2line::Context::new(&self.obj_file).unwrap();

        match addr {
            None => {
                let pc_offset = self.offset_loadaddr(self.get_pc());
                let res = ctx.find_location(pc_offset);
                if let Ok(Some(location)) = res {
                    self.print_source(&location, 10);
                }
            }
            Some(addr) => {
                unimplemented!()
            }
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
        let registers = self.get_registers();
        match info.si_code {
            TRAP_BRKPT | SI_KERNEL => {
                let current_pc = registers.rip;
                self.set_pc(current_pc - 1);
                let ctx = addr2line::Context::new(&self.obj_file).unwrap();
                let res = ctx.find_location(self.offset_loadaddr(current_pc - 1));
                if let (Ok(Some(location))) = res {
                    self.print_source(&location, 10);
                } else {
                    warn!("cannot find debug source file");
                }

                println!("Hit breakpoint at address: {:?}", current_pc);
            }
            TRAP_TRACE => {}
            _ => {
                warn!("unimplemented of sigtrap code: {:?}", info);
            }
        }
    }

    pub fn handle_quit(&mut self) {
        match self.state {
            State::Running => {
                println!("debugger is running, do you want to close is? (y/Y for close, other for cancel)");
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
}

fn tokens(input: &str) -> Vec<&str> {
    input
        .split(" ")
        .map(|s| s.trim().trim_end())
        .filter(|&v| v != "")
        .collect()
}

#[cfg(test)]
mod tests {

    #[test]
    fn t1() {
        let bin_data = std::fs::read("data/test").unwrap();
        let obj_file = object::File::parse(&*bin_data).unwrap();
        let ctx = addr2line::Context::new(&obj_file).unwrap();
        let _location = ctx
            .find_location(0x114b)
            // .find_location(dbg!(current_pc - 1 - self.load_addr as u64))
            .unwrap()
            .unwrap();
    }

    #[test]
    fn t2() {
        let bin_data = std::fs::read("data/test").unwrap();
        let obj_file = object::File::parse(&*bin_data).unwrap();
        let ctx = addr2line::Context::new(&obj_file).unwrap();
        let res = ctx
            .find_dwarf_unit(0x114b)
            // .find_location(dbg!(current_pc - 1 - self.load_addr as u64))
            .unwrap();
        dbg!(res);
    }
}
