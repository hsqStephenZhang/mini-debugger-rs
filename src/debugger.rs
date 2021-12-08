use libc::pid_t;
use rustyline::{error::ReadlineError, Editor};

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
}

#[allow(warnings)]
impl Debugger {
    pub fn new(prog_name: String, prog_pid: pid_t) -> Self {
        todo!()
    }

    pub fn set_breakpointer_at_address(&mut self, addr: usize) {
        todo!()
    }

    pub fn set_breakpointer_at_function(&mut self, addr: usize) {
        todo!()
    }

    pub fn set_breakpointer_at_source_line(&mut self, addr: usize) {
        todo!()
    }

    pub fn dump_registers(&self) {
        todo!()
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
        todo!()
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

    pub fn handle_command(&mut self, comm: &str) {}

    pub fn handle_sigtrap(&mut self) {
        todo!()
    }

    // ====== memory
    pub fn read_memory(&self, addr: usize) {
        todo!()
    }
    pub fn write_memory(&mut self, addr: usize, value: usize) {
        todo!()
    }

    pub fn wait_for_signal(&mut self) {
        unsafe {
            let mut wait_status = 0;
            let option = 0;
            libc::waitpid(self.prog_pid, &mut wait_status as _, option);

            let mut info = 0;
            libc::ptrace(
                libc::PTRACE_GETSIGINFO,
                self.prog_pid,
                0,
                &mut info as *mut _ as *mut libc::c_void,
            );
            dbg!(info);
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
                    // debugger.handle_command(&line);
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
