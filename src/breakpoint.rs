use libc::pid_t;

#[derive(Clone, Debug)]
pub struct BreakPoint {
    pub pid: pid_t,
    pub addr: usize,
    pub enabled: bool,
    pub saved_data: i64,
}

impl BreakPoint {
    pub fn new(pid: pid_t, addr: usize) -> Self {
        Self {
            pid,
            addr,
            enabled: false,
            saved_data: 0,
        }
    }

    pub fn enable(&mut self) {
        unsafe {
            let data = libc::ptrace(libc::PTRACE_PEEKDATA, self.pid, self.addr, 0);
            self.saved_data = data;
            let data_with_int3 = (data & !0xff) | 0xcc; // set the lower byte into 0xcc
            libc::ptrace(libc::PTRACE_POKEDATA, self.pid, self.addr, data_with_int3);
        }
        self.enabled = true;
    }

    pub fn disable(&mut self) {
        unsafe {
            let data = libc::ptrace(libc::PTRACE_PEEKDATA, self.pid, self.addr, 0);
            let restored_data = (data & !0xff) | self.saved_data; // put the low and high part together
            libc::ptrace(libc::PTRACE_POKEDATA, self.pid, self.addr, restored_data);
        }
        self.enabled = false;
    }
}
