mod abi;
mod api;
//mod decoder;
mod encoder;
mod error;
mod table;

#[cfg(test)]
mod test {
    use std::{
        alloc::Layout,
        fmt::Debug,
        fs::hard_link,
        marker::PhantomData,
        sync::{Arc, Mutex},
    };

    use crate::{
        abi::{
            registers_and_stack::{RegisterAndStackData, RegistersAndStackEncoder},
            Allocation, SyscallAbi,
        },
        api::{SyscallApi, SyscallEncodable},
        encoder::{DecodeError, EncodePrimitive, SyscallEncoder},
        error::SyscallError,
        syscall_api,
        table::SyscallTable,
    };

    struct NullAbi<RegisterType: Copy + Default, const NR_REGS: usize> {
        sender: Mutex<std::sync::mpsc::Sender<(u64, RegisterAndStackData<RegisterType, NR_REGS>)>>,
        rx: Mutex<std::sync::mpsc::Receiver<RegisterAndStackData<RegisterType, NR_REGS>>>,
        ksender: Mutex<std::sync::mpsc::Sender<RegisterAndStackData<RegisterType, NR_REGS>>>,
        krx: Mutex<std::sync::mpsc::Receiver<(u64, RegisterAndStackData<RegisterType, NR_REGS>)>>,
    }

    impl<RegisterType: Copy + Default, const NR_REGS: usize> NullAbi<RegisterType, NR_REGS> {
        fn new(
            sender: Mutex<
                std::sync::mpsc::Sender<(u64, RegisterAndStackData<RegisterType, NR_REGS>)>,
            >,
            rx: Mutex<std::sync::mpsc::Receiver<RegisterAndStackData<RegisterType, NR_REGS>>>,
            ksender: Mutex<std::sync::mpsc::Sender<RegisterAndStackData<RegisterType, NR_REGS>>>,
            krx: Mutex<
                std::sync::mpsc::Receiver<(u64, RegisterAndStackData<RegisterType, NR_REGS>)>,
            >,
        ) -> Self {
            Self {
                sender,
                rx,
                ksender,
                krx,
            }
        }
    }

    struct NullHandler<RegisterType: Copy + Default, const NR_REGS: usize> {
        abi: Arc<NullAbi<RegisterType, NR_REGS>>,
    }

    impl<RegisterType: Copy + Default, const NR_REGS: usize> NullHandler<RegisterType, NR_REGS> {
        fn new(abi: Arc<NullAbi<RegisterType, NR_REGS>>) -> Self {
            Self { abi }
        }
    }

    impl<'s, RegisterType: Copy + Default, const NR_REGS: usize> SyscallAbi
        for NullAbi<RegisterType, NR_REGS>
    where
        RegisterType: From<u8>,
        RegisterType: TryInto<u8>,
    {
        type SyscallArgType = RegisterAndStackData<RegisterType, NR_REGS>;

        type SyscallRetType = RegisterAndStackData<RegisterType, NR_REGS>;

        type SyscallNumType = u64;

        type ArgEncoder<'a> = RegistersAndStackEncoder<'a, Self, RegisterType, NR_REGS>
        where
            Self: 'a;
        type RetEncoder<'a> = RegistersAndStackEncoder<'a, Self, RegisterType, NR_REGS>
        where
            Self: 'a;

        fn with_alloc<F, R, E: Copy>(
            &self,
            layout: Layout,
            f: F,
        ) -> Result<R, crate::error::SyscallError<E>>
        where
            F: FnOnce(crate::abi::Allocation) -> Result<R, crate::error::SyscallError<E>>,
        {
            // TODO: fix layout
            alloca::with_alloca_zeroed(layout.size(), |ptr| {
                let alloc = ptr.into();
                f(alloc)
            })
        }

        fn kernel_alloc(&self, _layout: Layout) -> Allocation {
            Allocation::null()
        }

        fn syscall_impl(
            &self,
            num: Self::SyscallNumType,
            args: Self::SyscallArgType,
        ) -> Self::SyscallRetType {
            self.sender.lock().unwrap().send((num, args)).unwrap();
            self.rx.lock().unwrap().recv().unwrap()
        }
    }

    #[test]
    fn basic_test() {
        #[derive(Clone, Copy, Debug)]
        struct Foo {
            x: u32,
            y: u32,
        }

        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
        struct FooRet {
            a: u32,
            b: u32,
        }

        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
        enum FooErr {
            Sad,
        }

        impl<'a, Abi: SyscallAbi, RegisterType: Copy + Default, const NR_REGS: usize>
            SyscallEncodable<
                'a,
                Abi,
                RegisterAndStackData<RegisterType, NR_REGS>,
                Abi::ArgEncoder<'a>,
            > for Foo
        where
            RegisterType: From<u32>,
            RegisterType: TryInto<u32>,
            u32: TryFrom<RegisterType>,
            <Abi as SyscallAbi>::ArgEncoder<'a>:
                EncodePrimitive<'a, Abi, RegisterAndStackData<RegisterType, NR_REGS>, u32>,
        {
            fn encode(
                &self,
                encoder: &mut Abi::ArgEncoder<'a>,
            ) -> Result<(), crate::encoder::EncodeError> {
                self.x.encode(encoder)?;
                self.y.encode(encoder)?;
                Ok(())
            }

            fn decode(decoder: &mut Abi::ArgEncoder<'a>) -> Result<Self, DecodeError>
            where
                Self: Sized,
            {
                Ok(Self {
                    x: <u32>::decode(decoder)?,
                    y: <u32>::decode(decoder)?,
                })
            }
        }

        impl<'a, Abi: SyscallAbi, RegisterType: Copy + Default, const NR_REGS: usize>
            SyscallEncodable<
                'a,
                Abi,
                RegisterAndStackData<RegisterType, NR_REGS>,
                Abi::RetEncoder<'a>,
            > for FooRet
        where
            RegisterType: From<u32>,
            RegisterType: TryInto<u32>,
            u32: TryFrom<RegisterType>,
            <Abi as SyscallAbi>::RetEncoder<'a>:
                EncodePrimitive<'a, Abi, RegisterAndStackData<RegisterType, NR_REGS>, u32>,
        {
            fn encode(
                &self,
                encoder: &mut Abi::RetEncoder<'a>,
            ) -> Result<(), crate::encoder::EncodeError> {
                self.a.encode(encoder)?;
                self.b.encode(encoder)?;
                Ok(())
            }

            fn decode(decoder: &mut Abi::RetEncoder<'a>) -> Result<Self, DecodeError>
            where
                Self: Sized,
            {
                Ok(Self {
                    a: <u32>::decode(decoder)?,
                    b: <u32>::decode(decoder)?,
                })
            }
        }

        impl<'a, Abi: SyscallAbi, RegisterType: Copy + Default, const NR_REGS: usize>
            SyscallEncodable<
                'a,
                Abi,
                RegisterAndStackData<RegisterType, NR_REGS>,
                Abi::RetEncoder<'a>,
            > for FooErr
        where
            RegisterType: From<u32>,
            RegisterType: TryInto<u32>,
            u32: TryFrom<RegisterType>,
            <Abi as SyscallAbi>::RetEncoder<'a>:
                EncodePrimitive<'a, Abi, RegisterAndStackData<RegisterType, NR_REGS>, u32>,
        {
            fn encode(
                &self,
                encoder: &mut Abi::RetEncoder<'a>,
            ) -> Result<(), crate::encoder::EncodeError> {
                Ok(())
            }

            fn decode(decoder: &mut Abi::RetEncoder<'a>) -> Result<Self, DecodeError>
            where
                Self: Sized,
            {
                Ok(FooErr::Sad)
            }
        }
        impl<'a, Abi: SyscallAbi + 'a, RegisterType: Copy + Default, const NR_REGS: usize>
            SyscallApi<'a, Abi> for Foo
        where
            Abi: SyscallAbi<SyscallNumType = u64>,
            Abi: SyscallAbi<SyscallRetType = RegisterAndStackData<RegisterType, NR_REGS>>,
            Abi: SyscallAbi<SyscallArgType = RegisterAndStackData<RegisterType, NR_REGS>>,
            RegisterType: From<u32>,
            RegisterType: TryInto<u32>,
            u32: TryFrom<RegisterType>,
            <Abi as SyscallAbi>::ArgEncoder<'a>:
                EncodePrimitive<'a, Abi, RegisterAndStackData<RegisterType, NR_REGS>, u32>,

            <Abi as SyscallAbi>::RetEncoder<'a>:
                EncodePrimitive<'a, Abi, RegisterAndStackData<RegisterType, NR_REGS>, u32>,
        {
            type ReturnType = FooRet;

            const NUM: Abi::SyscallNumType = 1;

            type ErrorType = FooErr;
        }

        let foo = Foo { x: 34, y: 89 };
        let down = std::sync::mpsc::channel();
        let up: (
            std::sync::mpsc::Sender<RegisterAndStackData<u64, 8>>,
            std::sync::mpsc::Receiver<RegisterAndStackData<u64, 8>>,
        ) = std::sync::mpsc::channel();
        let abi = Arc::new(NullAbi::<u64, 8>::new(
            Mutex::new(down.0),
            Mutex::new(up.1),
            Mutex::new(up.0),
            Mutex::new(down.1),
        ));
        let handler = NullHandler::new(abi.clone());

        impl<'a, Abi: SyscallAbi + 'a, RegisterType: Copy + Default, const NR_REGS: usize>
            SyscallTable<Abi> for NullHandler<RegisterType, NR_REGS>
        where
            Abi: SyscallAbi<SyscallNumType = u64>,
            Abi: SyscallAbi<SyscallArgType = RegisterAndStackData<RegisterType, NR_REGS>>,
            Abi: SyscallAbi<SyscallRetType = RegisterAndStackData<RegisterType, NR_REGS>>,
            RegisterType: From<u32>,
            RegisterType: TryInto<u32>,
            RegisterType: From<u8>,
            RegisterType: TryInto<u8>,
            RegisterType: Debug,
            u32: TryFrom<RegisterType>,
            <Abi as SyscallAbi>::ArgEncoder<'a>:
                EncodePrimitive<'a, Abi, RegisterAndStackData<RegisterType, NR_REGS>, u32>,
            <Abi as SyscallAbi>::RetEncoder<'a>:
                EncodePrimitive<'a, Abi, RegisterAndStackData<RegisterType, NR_REGS>, u32>,
        {
            fn handle_call(
                &self,
                num: Abi::SyscallNumType,
                arg: Abi::SyscallArgType,
            ) -> Abi::SyscallRetType {
                let x = unsafe {
                    syscall_api! {
                        num, arg,
                        NullAbi<RegisterType, NR_REGS>,
                        &*self.abi,
                        (Foo, |_n, _foo| {
                            println!("::: HERE {:?}", _foo);
                            Ok(FooRet {
                                a: 33, b: 99
                            })
                        })
                    }
                };

                let layout = Layout::new::<
                    Result<
                        <Foo as SyscallApi<'a, Abi>>::ReturnType,
                        SyscallError<<Foo as SyscallApi<'a, Abi>>::ErrorType>,
                    >,
                >();
                let alloc = self.abi.kernel_alloc(layout);
                let mut encoder = self.abi.ret_encoder(alloc);

                // TODO: communicate this error
                let _ = x.encode(&mut encoder);
                let s = encoder.finish();
                println!(":: {:?}", s);
                s
            }
        }

        let thr = std::thread::spawn(move || {
            let (num, args) = handler.abi.krx.lock().unwrap().recv().unwrap();
            let ret = <NullHandler<u64, 8> as SyscallTable<NullAbi<u64, 8>>>::handle_call(
                &handler, num, args,
            );
            handler.abi.ksender.lock().unwrap().send(ret).unwrap();
        });

        let res = foo.perform_call(&*abi);
        thr.join().unwrap();

        assert_eq!(res, Ok(FooRet { a: 33, b: 99 }));
    }
}
