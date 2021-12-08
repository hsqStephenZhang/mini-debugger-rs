use structopt::StructOpt;

#[derive(StructOpt, Debug, Clone, PartialEq, Eq)]
#[structopt(about = "Gdb-rs commands")]
pub enum Gdb {
    Register { name: Option<String> },
    Breakpoint { addr: usize },
}

#[cfg(test)]
mod tests {
    use structopt::StructOpt;

    use super::Gdb;

    #[test]
    fn t1() {
        let args = vec!["gdb", "breakpoint", "123"];
        let a = Gdb::from_iter_safe(args.iter()).unwrap();
        assert_eq!(a, Gdb::Breakpoint { addr: 123 });
    }

    #[test]
    fn t2() {
        let args = vec!["gdb", "register", "rip"];
        let a = Gdb::from_iter_safe(args.iter()).unwrap();
        assert_eq!(
            a,
            Gdb::Register {
                name: Some("rip".into())
            }
        );
    }
}
