//! Prints its arguments and selected environment variables, then exits with
//! the status given by an `exit=N` argument.
fn main() {
    let mut status = 0;
    for (i, arg) in std::env::args().enumerate() {
        println!("arg[{i}]={arg}");
        if let Some(n) = arg.strip_prefix("exit=") {
            status = n.parse().expect("exit status");
        }
    }
    match std::env::var("FWE_GUEST_VAR") {
        Ok(v) => println!("FWE_GUEST_VAR={v}"),
        Err(_) => println!("FWE_GUEST_VAR unset"),
    }
    std::process::exit(status);
}
