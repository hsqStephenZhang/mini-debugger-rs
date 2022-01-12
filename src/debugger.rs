use std::{
    borrow::Cow,
    collections::HashMap,
    fs::File,
    io::{self, BufRead},
};

use iced_x86::{Formatter, NasmFormatter};
use libc::{pid_t, ptrace, siginfo_t};
use nix::{errno::Errno, unistd::Pid};
use object::{Object, ObjectSection, ObjectSymbol, Symbol};
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

pub struct Debugger<'a> {
    pub state: State,
    pub prog_name: String,
    pub prog_pid: pid_t,
    pub load_addr: usize,
    pub breakpoints: HashMap<u64, BreakPoint>,
    pub index_to_breakpoints: HashMap<usize, u64>,
    pub breakpoints_to_index: HashMap<u64, usize>,
    pub next_breakpoint_index: usize,
    pub obj_file: object::File<'a>,
    pub formatter: NasmFormatter,
}

#[allow(warnings)]
impl<'a> Debugger<'a> {
    pub fn new(prog_name: String, prog_pid: pid_t, ojb_file: object::File<'a>) -> Self {
        let mut formatter = NasmFormatter::new();

        formatter.options_mut().set_digit_separator("`");
        formatter.options_mut().set_first_operand_char_index(10);
        Self {
            state: State::NotRunning,
            prog_name,
            prog_pid,
            load_addr: 0,
            breakpoints: HashMap::new(),
            index_to_breakpoints: HashMap::new(),
            breakpoints_to_index: HashMap::new(),
            next_breakpoint_index: 0,
            obj_file: ojb_file,
            formatter,
        }
    }

    pub fn set_state(&mut self, state: State) {
        let s = &mut self.state;
        *s = state;
    }

    fn offset_loadaddr(&self, cur: u64) -> u64 {
        cur - self.load_addr as u64
    }

    pub fn print_source_raw(&self, filename: &str, line_idx: usize, num_lines: usize) {
        // info!("reading source file:{:?}, line: {:?}", filename, line_idx);
        match crate::utils::read_lines(filename) {
            Ok(lines) => {
                for (idx, line) in lines
                    .into_iter()
                    .enumerate()
                    .skip(line_idx as usize)
                    .take(num_lines)
                {
                    println!("  {}: {}", idx, line.unwrap());
                }
            }
            Err(e) => println!("read source file err: {:?}", e),
        }
    }

    pub fn print_source(&self, location: &addr2line::Location, num_lines: usize) {
        if let (Some(filename), Some(line_idx)) = (location.file, location.line) {
            self.print_source_raw(filename, line_idx as usize - 1, num_lines);
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

    pub fn remove_breakpointer_at_index(&mut self, index: usize) {
        let addr = self.index_to_breakpoints.remove(&index);
        if let Some(addr) = addr {
            self.remove_breakpointer_at_address(addr);
            self.breakpoints_to_index.remove(&addr);
        }
    }

    pub fn remove_breakpointer_at_address(&mut self, addr: u64) {
        let breakpoint = self.breakpoints.remove(&addr);
        if let Some(mut b) = breakpoint {
            let addr = b.addr;
            let index = self.breakpoints_to_index.remove(&addr).unwrap();
            self.index_to_breakpoints.remove(&index);
            b.disable();
        }
    }

    fn lookup_symbol(&self, name: &str) -> Option<Symbol> {
        let iter = self.obj_file.symbols();
        for symbol in iter {
            if symbol.name() == Ok(name) {
                return Some(symbol);
            }
        }
        return None;
    }

    pub fn set_breakpointer_at_address(&mut self, addr: u64) {
        let mut breakpoint = BreakPoint::new(self.prog_pid, addr);
        breakpoint.enable();
        self.breakpoints.insert(addr, breakpoint);
        let index = self.next_breakpoint_index;
        // two direction hashmap
        self.index_to_breakpoints.insert(index, addr);
        self.breakpoints_to_index.insert(addr, index);
        self.next_breakpoint_index += 1;
    }

    pub fn set_breakpointer_at_function(&mut self, name: &str) {
        if let Some(symbol) = self.lookup_symbol(name) {
            let pc = symbol.address();
            self.set_breakpointer_at_address(pc + self.load_addr as u64);
        }
    }

    pub fn set_breakpointer_at_source_line(
        &mut self,
        filename: Option<&str>,
        line_offset: Option<u32>,
    ) {
        let ctx = addr2line::Context::new(&self.obj_file).unwrap();
        let mut res = ctx.find_location_range(0, u64::MAX).unwrap();
        while let Some((addr, len, location)) = res.next() {
            let addr2line::Location { file, line, column } = location;
            if file == filename && line == line_offset {
                self.set_breakpointer_at_address(addr + self.load_addr as u64);
                return;
            }
        }
    }

    pub fn dump_breakpoints(&self) {
        for (index, addr) in self.index_to_breakpoints.iter() {
            let breakpoint = &self.breakpoints[addr];
            let status = if breakpoint.enabled {
                "enabled"
            } else {
                "disabled"
            };
            println!(
                "{:<5}: 0x{:x?}, status:{}, saved data:0x{:x?}",
                index, breakpoint.addr, status, breakpoint.saved_data
            );
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
        println!("registers:\n{:x?}", registers);
    }

    pub fn dump_register(&self, name: &str) {
        let mut registers = self.get_registers();
        let register = self.name_to_register(&mut registers, name);
        match register {
            Some(r) => {
                println!("{} : 0x{:x}", name, r);
            }
            None => println!("register name not found: {}", name),
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

    // if step one int3 instruction, nothing happens(reset)
    pub fn single_step_instruction(&mut self) {
        unsafe {
            ptrace(libc::PTRACE_SINGLESTEP, self.prog_pid, 0, 0);
            self.wait_for_signal();
        }
    }

    pub fn single_step_instruction_with_breakpoint_check(&mut self) {
        let pc = self.get_pc();
        if let Some(v) = self.breakpoints.get(&pc) {
            self.step_over_breakpoint(pc);
        } else {
            self.single_step_instruction();
        }
    }

    pub fn get_line_location_from_cur(&self) -> Option<(String, u32)> {
        let mut pc = self.offset_loadaddr(self.get_pc());
        let ctx = addr2line::Context::new(&self.obj_file).unwrap();
        let location = ctx.find_location(pc);
        if let Ok(Some(loc)) = location {
            let file = loc.file;
            let line = loc.line;
            match (file, line) {
                (Some(f), Some(l)) => return Some((f.to_owned(), l)),
                _ => return None,
            }
        } else {
            None
        }
    }

    // mostly used when there is a breakpoint at current rip
    // if there is a breakpoint at this point, we will:
    //      1. disable the breakpoint, restore the instruction
    //      2. ptrace single step, execute this instruction, after it, will trigger sigtrap
    //      3. waitpid, handle the sigtrap
    //      4. enable the breakpoint
    pub fn step_over_breakpoint(&mut self, breakpoint_addr: u64) -> u64 {
        let breakpoint = self.breakpoints.remove(&breakpoint_addr);
        if let Some(mut b) = breakpoint {
            if b.enabled {
                b.disable();
                unsafe {
                    ptrace(libc::PTRACE_SINGLESTEP, self.prog_pid, 0, 0);
                    self.wait_for_signal();
                }
                b.enable();
            }
            self.breakpoints.insert(breakpoint_addr, b);
        }
        return breakpoint_addr;
    }

    pub fn continue_exec(&mut self) -> Result<(), Errno> {
        // ptrace(PTRACE_CONT, ...) can let the tracee continue to run
        unsafe {
            self.step_over_breakpoint(self.get_pc());
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
                Gdb::Finish => self.handle_finish(),
                Gdb::Info { info } => self.handle_info(info),
                Gdb::Next => self.handle_next(),
                Gdb::Nexti => self.handle_nexti(),
                Gdb::Memory { memory } => self.handle_memory(memory),
                Gdb::Quit => self.handle_quit(),
                Gdb::Source { addr } => self.handle_source(addr),
                Gdb::Step => self.handle_step(),
                Gdb::Stepi => self.handle_stepi(),
                _ => {}
            },
            Err(e) => {
                println!("error:{:}", e);
            }
        }
    }

    pub fn handle_backtrace(&self) {
        let mut frame_number = 0;

        let mut frame_dumper = |func_name: &Cow<str>, func_location: addr2line::Location| {
            frame_number += 1;

            println!(
                "frame #{}, {:?} at {} line {}",
                frame_number,
                func_name,
                func_location.file.unwrap_or(""),
                func_location.line.unwrap_or(0)
            );
        };

        let mut pc = self.offset_loadaddr(self.get_pc());
        let ctx = addr2line::Context::new(&self.obj_file).unwrap();
        let mut res;

        // unwind frame poitner
        'outer: loop {
            res = ctx.find_frames(pc);
            match res {
                Ok(mut frame_iter) => {
                    while let Ok(Some(f)) = frame_iter.next() {
                        let func_name = f.function;
                        let func_location = f.location;
                        if let (Some(func_name), Some(func_location)) = (func_name, func_location) {
                            let name = func_name.raw_name().unwrap();
                            frame_dumper(&name, func_location);

                            if name == Cow::Borrowed("main") {
                                return;
                            } else {
                                let rbp = self.get_registers().rbp;
                                let return_address_loc = rbp + 8;
                                let return_address = self.read_memory(return_address_loc as usize);
                                pc = self.offset_loadaddr(return_address as u64);
                                continue 'outer;
                            }
                        }
                    }
                    break;
                }
                err => {
                    warn!("no backtrace at this position, pc={}", pc);
                }
            }
        }
    }

    pub fn handle_breakpoint(&mut self, addr: String) {
        if addr.starts_with("*") {
            let addr = str_to_u64(&addr[1..]);
            match addr {
                Ok(addr) => {
                    self.set_breakpointer_at_address(addr);
                }
                Err(name) => {
                    warn!("error parsing the address value:{}", name);
                }
            }
            return;
        }

        // line offset
        if addr.starts_with("+") || addr.starts_with("-") {
            let pc = self.offset_loadaddr(self.get_pc());
            let ctx = addr2line::Context::new(&self.obj_file).unwrap();
            // 1. find current line
            let location = ctx.find_location(pc);
            if let Ok(Some(loc)) = location {
                let filename = loc.file;
                let line = loc.line.unwrap();
                // 2. parse the line offset
                let offset = addr.parse::<i64>();
                match offset {
                    Ok(res) => {
                        // 3. get the real line number
                        let line_idx = (line as i64 + res) as u32;
                        self.set_breakpointer_at_source_line(filename, Some(line_idx))
                    }
                    Err(err) => {
                        warn!("error parsing line offset");
                    }
                }
            }

            return;
        }

        if addr.contains(":") {
            let strings: Vec<&str> = addr.split(":").collect();
            if strings.len() == 2 {
                let r = strings[1].parse::<u32>();
                if let Ok(line) = r {
                    self.set_breakpointer_at_source_line(Some(strings[0]), Some(line));
                }
            }
        }

        if let Some(sym) = self.lookup_symbol(&addr) {
            let kind = sym.kind();
            if object::SymbolKind::Text == kind {
                let addr = sym.address() + self.load_addr as u64;
                self.set_breakpointer_at_address(addr);
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

    pub fn handle_disable(&mut self, index: usize) {
        if let Some(addr) = self.index_to_breakpoints.get(&index) {
            let breakpoint = self.breakpoints.get_mut(addr).unwrap();
            breakpoint.disable();
        } else {
            println!("no breakpoint of index {:?}", index);
        }
    }

    pub fn get_current_func_name(&self) -> Option<String> {
        let ctx = addr2line::Context::new(&self.obj_file).unwrap();

        let pc = self.offset_loadaddr(self.get_pc());
        let mut frame_iter = ctx.find_frames(pc);
        if let Ok(mut iter) = frame_iter {
            if let Ok(Some(frame)) = iter.next() {
                let name = frame.function.unwrap();
                let name = name.raw_name().unwrap();
                return Some(name.to_string());
            }
        }
        return None;
    }

    pub fn handle_disassemble(&mut self, addr: Option<String>) {
        // let func_name=self.get_func_name_from_name(addr)
        let name = match addr {
            Some(name) => name,
            None => {
                if let Some(name) = self.get_current_func_name() {
                    name
                } else {
                    String::new()
                }
            }
        };
        let symbol = self.lookup_symbol(&name);
        if let Some(sym) = symbol {
            let addr = sym.address();
            let size = sym.size();

            println!(
                "\"{}\" starts at 0x{:x} and ends at 0x{:x}",
                name,
                addr + self.load_addr as u64,
                addr + self.load_addr as u64 + size
            );

            let idx = sym.section().index();
            if let Some(idx) = idx {
                let section = self.obj_file.section_by_index(idx).unwrap();
                let content = section.data_range(addr, size);
                if let Ok(Some(content)) = content {
                    crate::utils::disassemble(content, 64, addr + self.load_addr as u64, 10);
                }
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

    pub fn handle_finish(&mut self) {
        let rbp = self.get_registers().rbp;
        let return_address_loc = rbp + 8;
        let return_address = self.read_memory(return_address_loc as usize) as u64;
        info!("the return address is: 0x{:x?}", return_address);
        let should_remove_breakpoint = if let Some(_) = self.breakpoints.get(&return_address) {
            false
        } else {
            true
        };

        self.set_breakpointer_at_address(return_address);
        self.continue_exec();

        if should_remove_breakpoint {
            self.remove_breakpointer_at_address(return_address);
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
            Info::Line { name } => {
                if let Some(symbol) = self.lookup_symbol(&name) {
                    let addr = symbol.address();
                    let size = symbol.size();
                    println!(
                        "\"{}\" starts at 0x{:x} and ends at 0x{:x}",
                        name,
                        addr,
                        addr + size
                    );
                } else {
                    println!("Function \"{}\" not defined", name)
                }
            }
        }
    }

    pub fn handle_next(&mut self) {
        let ctx = addr2line::Context::new(&self.obj_file).unwrap();
        let res = ctx.find_location(self.offset_loadaddr(self.get_pc()));
        if let Ok(Some(loc)) = res {
            loop {
                self.handle_nexti();
                let new_res = ctx.find_location(self.offset_loadaddr(self.get_pc()));
                if let Ok(Some(new_loc)) = new_res {
                    if loc.file == new_loc.file && loc.line == new_loc.line {
                        self.print_source_raw(loc.file.unwrap(), loc.line.unwrap() - 1, 1);
                        continue;
                    }
                }
                return;
            }
        }
    }

    // single step a instruction, can get into a function
    pub fn handle_nexti(&mut self) {
        let pc = self.get_pc();
        if let Some(v) = self.breakpoints.get(&pc) {
            let content = v.saved_data;
            let res: [u8; 8] = unsafe { std::mem::transmute(content) };
            // if this is a call
            if res[0] == 0xe8 {
                // info!("this is one call instruction at 0x{:x}", pc);
                let return_address = pc + 5;
                self.set_breakpointer_at_address(return_address);
                self.continue_exec();
                self.remove_breakpointer_at_address(return_address);
            } else {
                self.step_over_breakpoint(pc);
            }
        } else {
            self.single_step_instruction();
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
                // info!("reset pc to 0x{:x}", current_pc - 1);
                let res = ctx.find_location(self.offset_loadaddr(current_pc - 1));
                if let (Ok(Some(location))) = res {
                    self.print_source(&location, 1);
                } else {
                    warn!("cannot find debug source file");
                }

                println!("Hit breakpoint at address: 0x{:x?}", current_pc - 1);
            }
            TRAP_TRACE => {}
            _ => {
                warn!(
                    "unimplemented of sigtrap code: signo: 0x{:x?}, errno: 0x{:x?}",
                    info.si_signo, info.si_errno
                );
            }
        }
    }

    // TODO: use addr
    pub fn handle_source(&mut self, addr: Option<String>) {
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
                let symbol = self.lookup_symbol(&addr);
                if let Some(sym) = symbol {
                    let addr = sym.address();
                    let res = ctx.find_location(addr);
                    if let Ok(Some(location)) = res {
                        self.print_source(&location, 10);
                    }
                }
            }
        }
    }

    // single step until next line in source code, can get into a function
    pub fn handle_step(&mut self) {
        if let Some((file, line)) = self.get_line_location_from_cur() {
            loop {
                self.single_step_instruction_with_breakpoint_check();
                if let Some((new_file, new_line)) = self.get_line_location_from_cur() {
                    if new_file != file || new_line != line {
                        self.print_source_raw(&new_file, new_line as usize - 1, 1);
                        return;
                    }
                } else {
                    return;
                }
            }
        } else {
            // debug info not found
            self.single_step_instruction_with_breakpoint_check();
        }
    }

    // single step, can get into a function
    pub fn handle_stepi(&mut self) {
        self.single_step_instruction_with_breakpoint_check();
    }

    // ====== x86 decode, for print instruction =====
    pub fn decode_one(&self, bytes: &[u8]) -> iced_x86::Instruction {
        let mut decoder = iced_x86::Decoder::with_ip(64, bytes, 0, iced_x86::DecoderOptions::NONE);
        decoder.decode()
    }

    pub fn decode_at(&mut self, pc: usize) {
        let bytes: [u8; 8] = unsafe { std::mem::transmute(self.read_memory(pc as usize)) };
        let instruction = self.decode_one(&bytes[..]);
        self.dump_single_instruction(&instruction);
    }

    pub fn dump_single_instruction(&mut self, instruction: &iced_x86::Instruction) {
        let mut res = String::new();
        self.formatter.format(&instruction, &mut res);
        println!("instruction: {}", res);
    }

    // ====== memory =====
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
                    // when nexti, may face sigsegv
                    self.set_pc(self.get_pc() - 1);
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

    pub fn trace_instructions(&mut self, until_addr: u64) {
        // loop {
        //     let addr = self.step_over_breakpoint();
        //     if addr == until_addr {
        //         break;
        //     } else {
        //     }
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
    use object::{Object, ObjectSymbol};

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
        let iter = obj_file.symbols();
        for symbol in iter {
            if symbol.name() == Ok("f1") {
                dbg!(symbol);
            }
        }
    }
}
