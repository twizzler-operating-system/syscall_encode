use crate::abi::SyscallAbi;

#[macro_export]
macro_rules! syscall_api {
    (
        number = $in_num:expr;
        args = $in_args:expr;
        abi_type = $abitype:ty;
        abi = $abi:expr;
        handlers = { $(($type:ty, $call:expr)),* }
        fast_handlers = { $(($fasttype:ty, $fastcall:expr)),* }
    ) => {
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
            $(
                <$fasttype as SyscallFastApi<$abitype>>::NUM => {
                    let args: $fasttype = $in_args.into();
                    let ret = $fastcall(<$fasttype as SyscallFastApi<$abitype>>::NUM, args);
                    ret.into()
                }
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
