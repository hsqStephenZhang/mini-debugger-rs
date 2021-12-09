use structopt::StructOpt;

#[derive(StructOpt, Debug, Clone, PartialEq, Eq)]
#[structopt(about = "Gdb-rs commands")]
pub enum Gdb {
    Quit,
    // break point related commands
    Break {
        addr: String,
    },
    Enable {
        index: usize,
    },
    Disable {
        index: usize,
    },
    // debug utils
    Continue,
    Step,
    Next,
    Stepi,
    Nexti,
    Memory {
        #[structopt(subcommand)]
        memory: Memory,
    },
    Info {
        #[structopt(subcommand)]
        info: Info,
    },
}

#[derive(StructOpt, Debug, Clone, PartialEq, Eq)]
#[structopt(about = "momory operations")]
pub enum Memory {
    Read { addr: String },
    Write { addr: String, value: String }, // we must handle both `100` and `0x123` type value
}

#[derive(StructOpt, Debug, Clone, PartialEq, Eq)]
#[structopt(about = "more infomations")]
pub enum Info {
    // display all breakpoints
    Breakpoints,
    Registers,
    Register { name: Option<String> },
}

pub fn into_gdb(args: Vec<&str>) -> Result<Gdb, clap::Error> {
    let iter = std::iter::once("gdb").chain(args.into_iter());
    Gdb::from_iter_safe(iter)
}

#[cfg(test)]
mod tests {
    use structopt::StructOpt;

    use crate::command::{Info, Memory};

    use super::Gdb;

    #[test]
    fn test_breakpoint() {
        let args = vec!["gdb", "break", "0x123"];
        let a = Gdb::from_iter_safe(args.iter()).unwrap();
        assert_eq!(
            a,
            Gdb::Break {
                addr: "0x123".into()
            }
        );

        let args = vec!["info", "breakpoints"];
        let iter = std::iter::once("gdb").chain(args.into_iter());
        let a = Gdb::from_iter_safe(iter).unwrap();
        assert_eq!(
            a,
            Gdb::Info {
                info: Info::Breakpoints
            }
        );
    }

    #[test]
    fn test_register() {
        let args = vec!["gdb", "info", "register", "rip"];
        let a = Gdb::from_iter_safe(args.iter()).unwrap();
        assert_eq!(
            a,
            Gdb::Info {
                info: Info::Register {
                    name: Some("rip".into())
                }
            }
        );
    }

    #[test]
    fn test_memory() {
        let args = vec!["gdb", "memory", "read", "0x123"];
        let a = Gdb::from_iter_safe(args.iter()).unwrap();
        assert_eq!(
            a,
            Gdb::Memory {
                memory: Memory::Read {
                    addr: "0x123".into()
                }
            }
        );

        let args = vec!["gdb", "memory", "write", "0x123", "100"];
        let a = Gdb::from_iter_safe(args.iter()).unwrap();
        assert_eq!(
            a,
            Gdb::Memory {
                memory: Memory::Write {
                    addr: "0x123".into(),
                    value: "100".into()
                }
            }
        );
    }

    #[test]
    fn test_enable_disable() {
        let args = vec!["gdb", "enable", "123"];
        let a = Gdb::from_iter_safe(args.iter()).unwrap();
        assert_eq!(a, Gdb::Enable { index: 123 });

        let args = vec!["gdb", "disable", "123"];
        let a = Gdb::from_iter_safe(args.iter()).unwrap();
        assert_eq!(a, Gdb::Disable { index: 123 })
    }
}
