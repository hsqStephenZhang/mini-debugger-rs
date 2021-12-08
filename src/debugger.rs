use std::collections::HashMap;

use libc::{pid_t, ptrace};
use rustyline::{error::ReadlineError, Editor};

use crate::breakpoint::BreakPoint;

#[derive(Debug, Clone)]
pub enum Symbol {
    None,
    Object,
    Func,
    Section,
    File,
}

pub struct Debugger {
    pub prog_name: String,
    pub prog_pid: pid_t,
    pub load_addr: usize,
    pub breakpoints: HashMap<usize, BreakPoint>,
}

#[allow(warnings)]
impl Debugger {
    pub fn new(prog_name: String, prog_pid: pid_t) -> Self {
        Self {
            prog_name,
            prog_pid,
            load_addr: 0,
            breakpoints: HashMap::new(),
        }
    }

    pub fn set_breakpointer_at_address(&mut self, addr: usize) {
        let breakpoint = BreakPoint::new(self.prog_pid, addr);
        self.breakpoints.insert(addr, breakpoint);
    }

    pub fn set_breakpointer_at_function(&mut self, addr: usize) {
        todo!()
    }

    pub fn set_breakpointer_at_source_line(&mut self, addr: usize) {
        todo!()
    }

    pub fn dump_registers(&self) {
        unsafe {
            let mut registers: libc::user_regs_struct =
                std::mem::MaybeUninit::uninit().assume_init();
            let p = &mut registers as *mut _ as *mut libc::c_void;
            ptrace(libc::PTRACE_GETREGS, self.prog_pid, 0, p);
            println!("{:X?}", registers);
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
        if comm.starts_with("continue") {
            self.continue_exec();
        } else if comm.starts_with("break") {
            let parts = tokens(comm);
            if parts.len() >= 2 {
                let addr: usize = parts[1].parse().unwrap();
                self.set_breakpointer_at_address(addr);
            } else {
                println!("please input a valid break point address");
            }
        } else if comm.starts_with("info") {
            let parts = tokens(comm);
            if parts.len() >= 2 {
                self.handle_info(parts[1]);
            } else {
                println!("please input the specified info type");
            }
        } else if comm.starts_with("memory") {
            let parts = tokens(comm);
            if parts.len() >= 3 {
            } else {
                println!("please input the ");
            }
        } else {
            println!("not supported command:{}", comm);
        }
    }

    pub fn handle_sigtrap(&mut self) {
        todo!()
    }

    pub fn handle_info(&self, info_type: &str) {
        if info_type == "register" {
            self.dump_registers();
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
        // `()` can be used when no completer is required
        let mut rl = Editor::<()>::new();
        if rl.load_history(".gdbrs.history").is_err() {
            println!("No previous history.");
        }
        // let mut debugger =Debugger::new();
        loop {
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
        .filter(|&v| v != " ")
        .map(|s| s.trim())
        .collect()
}
