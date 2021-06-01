pub fn roundup(x: usize, align: usize) -> usize {
    (x + align - 1) & !(align - 1)
}

#[macro_export]
macro_rules! emit {
    ($fmt:expr) => (print!(concat!("\t", $fmt, "\n")));
    ($fmt:expr, $($arg:tt)*) => (print!(concat!("\t", $fmt, "\n"), $($arg)*))
}

#[macro_export]
macro_rules! mov {
    ($src:expr, $dest:expr) => (emit!("mov {}, {}", stringify!($src), stringify!($dest)))
}

#[macro_export]
macro_rules! movzb {
    ($src:expr, $dest:expr) => (emit!("movzb {}, {}", $src, $dest))
}

#[macro_export]
macro_rules! lea {
    ($src:expr, $dest:expr) => (emit!("lea {}, {}", $src, $dest))
}

#[macro_export]
macro_rules! sub {
    ($src:expr, $dest:expr) => (emit!("sub {}, {}", $src, $dest))
}

#[macro_export]
macro_rules! add {
    ($src:expr, $dest:expr) => (emit!("add {}, {}", $src, $dest))
}

#[macro_export]
macro_rules! mul {
    ($src:expr) => (emit!("mul {}", $src))
}

#[macro_export]
macro_rules! div {
    ($src:expr) => (emit!("div {}", $src))
}

#[macro_export]
macro_rules! neg {
    ($src:expr) => (emit!("neg {}", $src))
}

#[macro_export]
macro_rules! cqo {
    () => (emit!("cqo"))
}

#[macro_export]
macro_rules! cmp {
    ($src:expr, $dest:expr) => (emit!("cmp {}, {}", $src, $dest))
}

#[macro_export]
macro_rules! shl {
    ($src:expr, $dest:expr) => (emit!("shl {}, {}", $src, $dest))
}

#[macro_export]
macro_rules! shr {
    ($src:expr, $dest:expr) => (emit!("shr {}, {}", $src, $dest))
}

#[macro_export]
macro_rules! push {
    ($src:expr) => (emit!("push {}", $src))
}

#[macro_export]
macro_rules! pop {
    ($dest:expr) => (emit!("pop {}", $dest))
}

#[macro_export]
macro_rules! ret {
    () => (emit!("ret"))
}

#[macro_export]
macro_rules! sete {
    ($dest:expr) => (emit!("sete {}", $dest))
}

#[macro_export]
macro_rules! setne {
    ($dest:expr) => (emit!("setne {}", $dest))
}

#[macro_export]
macro_rules! setl {
    ($dest:expr) => (emit!("setl {}", $dest))
}

#[macro_export]
macro_rules! setle {
    ($dest:expr) => (emit!("setle {}", $dest))
}
