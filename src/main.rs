use libc::fork;
use std::fs;
use std::{ffi::CString, process::exit};

#[macro_use]
extern crate log;
extern crate simple_logger;

use crate::debugger::Debugger;

pub mod breakpoint;
pub mod command;
pub mod debugger;
pub mod expr;
pub mod utils;

fn main() {
    simple_logger::init_with_level(log::Level::Info).unwrap();
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
            let bin_data = fs::read(prog.clone()).expect("read object file failed");
            let obj_file = object::File::parse(&*bin_data).expect("parse object content failed");
            let mut debugger = Debugger::new(prog, pid, obj_file);

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

    // dbg!(r);
    let prog_ctr = CString::new(prog).unwrap();
    libc::execl(prog_ctr.as_ptr(), prog_ctr.as_ptr(), 0);
}
