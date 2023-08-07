use crate::abi::SyscallAbi;

#[macro_export]
macro_rules! syscall_api {
    ($in_num:expr, $in_args:expr, $abitype:ty, $abi:expr, $(($type:ty, $call:expr)),*) => {
        {

    use syscall_macros_traits::encoder::SyscallEncoder;
    use syscall_macros_traits::api::SyscallEncodable;
        let res = match $in_num {
            $(
                <$type as SyscallApi<$abitype>>::NUM => {
                    let r = <$type as SyscallApi<$abitype>>::with($abi, $in_num, $in_args, $call);

                    let layout = core::alloc::Layout::new::<
                        Result<
                            <$type as SyscallApi<'a, $abitype>>::ReturnType,
                            SyscallError<<$type as SyscallApi<'a, $abitype>>::ErrorType>,
                        >,
                    >();

                    let alloc = $abi.kernel_alloc(layout);
                    let mut encoder = $abi.ret_encoder(alloc);

                    // TODO: communicate this error
                    let _ = r.encode(&mut encoder);
                    let s = encoder.finish();
                    s
                },
            )*
            _ => {
                    let layout = core::alloc::Layout::new::<
                        Result<
                            (),
                            SyscallError<()>,
                        >,
                    >();
                    let alloc = $abi.kernel_alloc(layout);
                    let mut encoder = $abi.ret_encoder(alloc);

                    // TODO: communicate this error
                    let e: Result<(), SyscallError<()>> = Err(SyscallError::InvalidNum);
                    let _ = e.encode(&mut encoder);
                    let s = encoder.finish();
                    s
               }
        };



        res
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
