use crate::abi::SyscallAbi;

#[macro_export]
macro_rules! syscall_api {
    ($in_num:expr, $in_args:expr, $abitype:ty, $abi:expr, $(($type:ty, $call:expr)),*) => {
        {
        let res = match $in_num {
            $(
                <$type as SyscallApi<$abitype>>::NUM => {
                    <$type as SyscallApi<$abitype>>::with($abi, $in_num, $in_args, $call)
                },
            )*
            _ => todo!()
        };
        todo!()

    }
    };
}

pub trait SyscallTable<Abi: SyscallAbi> {
    fn handle_call(
        &self,
        num: Abi::SyscallNumType,
        arg: Abi::SyscallArgType,
    ) -> Abi::SyscallRetType;
}
