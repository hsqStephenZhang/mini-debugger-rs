use libc::pid_t;

#[derive(Clone, Debug)]
pub struct BreakPoint {
    pub(crate) pid: pid_t,
    pub(crate) addr: u64,
    pub(crate) enabled: bool,
    pub(crate) saved_data: i64,
}

impl BreakPoint {
    pub fn new(pid: pid_t, addr: u64) -> Self {
        Self {
            pid,
            addr,
            enabled: false,
            saved_data: 0,
        }
    }

    pub fn enable(&mut self) {
        if !self.enabled {
            unsafe {
                let data = libc::ptrace(libc::PTRACE_PEEKDATA, self.pid, self.addr, 0);
                let _bytes = data.to_ne_bytes();
                self.saved_data = data;
                // info!("breakpoint saved data: {:x?}", _bytes);
                let data_with_int3 = (data & !0xff) | 0xcc; // set the lower byte into 0xcc
                libc::ptrace(libc::PTRACE_POKEDATA, self.pid, self.addr, data_with_int3);
            }
            self.enabled = true;
        } else {
            println!("this breakpoint is enabled");
        }
    }

    pub fn disable(&mut self) {
        if self.enabled {
            unsafe {
                let data = libc::ptrace(libc::PTRACE_PEEKDATA, self.pid, self.addr, 0);
                let restored_data = (data & !0xff) | self.saved_data; // put the low and high part together
                // info!(
                //     "to be restored data: {:x?}",
                //     restored_data.to_ne_bytes()
                // );
                libc::ptrace(libc::PTRACE_POKEDATA, self.pid, self.addr, restored_data);
            }
            self.enabled = false;
        } else {
            println!("this breakpoint is disabled");
        }
    }
}

