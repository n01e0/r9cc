pub fn roundup(x: usize, align: usize) -> usize {
    (x + align - 1) & !(align - 1)
}

#[macro_export]
macro_rules! emit {
    ($fmt:expr) => (print!(concat!("\t", $fmt, "\n")));
    ($fmt:expr, $($arg:tt)*) => (print!(concat!("\t", $fmt, "\n"), $($arg)*))
}
