use std::{ffi::CString, process::exit};

use libc::fork;

use crate::debugger::Debugger;

pub mod breakpoint;
pub mod command;
pub mod debugger;
pub mod utils;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        println!("no program specified");
        exit(1);
    }

    let prog = args[1].clone();

    unsafe {
        let pid = fork();
        if pid == 0 {
            libc::personality(libc::ADDR_NO_RANDOMIZE as libc::c_ulong);
            execute_debuggee(&prog);
        } else if pid >= 1 {
            println!("starting debugger process");
            let mut debugger = Debugger::new(prog, pid);

            match debugger.wait_for_signal() {
                Ok(_) => debugger.run(),
                Err(e) => println!("error:{:?}", e),
            }
        }
    }
}

unsafe fn execute_debuggee(prog: &str) {
    let r = libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0);
    if r < 0 {
        println!("error in ptrace");
    }

    dbg!(r);

    let prog_ctr = CString::new(prog).unwrap();
    libc::execl(prog_ctr.as_ptr(), prog_ctr.as_ptr(), 0);
}
