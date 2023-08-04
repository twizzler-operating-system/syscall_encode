use crate::SyscallRegister;

#[macro_export]
macro_rules! syscall_api {
    ($in_num:expr, $args:expr, $bits:expr, $nr_regs:expr, $reg:ty, $(($type:ty, $call:expr)),*) => {
        match $in_num {
            $(
                <$type as ::syscall_macros_traits::table::SyscallApi<$reg>>::NUM => <$type as ::syscall_macros_traits::SyscallArguments<$bits, $nr_regs>>::with($in_num, $args, $call),
            )*
            _ => Err(::syscall_macros_traits::DecodeError::InvalidNum)
        }
    };
}

pub trait SyscallApi<T: SyscallRegister> {
    const NUM: T;
}
