use crate::abi::SyscallAbi;

/// Define the entire syscall table based on types that implement SyscallApi and SyscallFastApi. Also
/// acts as the match statement for that table, and so takes in the syscall number and args for the syscall
/// we are handling. For example:
///
/// ```no_compile
/// struct Foo {...};
/// impl SyscallApi<...> for Foo {
///     ...
/// }
/// struct FastFoo {...};
/// impl SyscallFastApi<...> for Foo {
///     ...
/// }
///
/// fn handle(num: NumType, args: ArgType) -> RetType {
///     let abi = X86Abi::default();
///     syscall_api! {
///         // The number of the incoming
///         number = num;
///         // The incoming args.
///         args = args;
///         // The type of the ABI we are using.
///         abi_type = X86Abi;
///         // An instance of that ABI.
///         abi = abi;
///         // List of handlers.
///         handlers = {
///             (Foo, |num, foo| {
///                 ...;
///                 Ok(FooRet{...})
///             }), ...
///         }
///         // List of handlers that use the Fast API.
///         fast_handlers = {
///             (FastFoo, |num, foo| {
///                 ...;
///                 FastFooRet{...}
///             }), ...
///         }
///     }
/// }
/// ```
///
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
        use syscall_encode_traits::encoder::SyscallEncoder;
        use syscall_encode_traits::api::SyscallEncodable;
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

                    if r.encode(&mut encoder).is_err() {
                        $abi.unrecoverable_encoding_failure(r)
                    }
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

                    let e: Result<(), SyscallError<()>> = Err(SyscallError::InvalidNum);
                    if e.encode(&mut encoder).is_err() {
                        $abi.unrecoverable_encoding_failure(e)
                    }
                    let s = encoder.finish();
                    s
               }
        };



        res
    }
    };
}

/// Defines a function for handling incoming syscalls, before decoding.
pub trait SyscallTable<Abi: SyscallAbi> {
    fn handle_call(
        &self,
        num: Abi::SyscallNumType,
        arg: Abi::SyscallArgType,
    ) -> Abi::SyscallRetType;
}
