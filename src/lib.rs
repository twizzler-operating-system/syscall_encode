//!
//! # Pointers and References
//! ```compile_fail
//! #[derive(syscall_macros::SyscallEncode, Debug, Clone, Eq, PartialEq, PartialOrd)]
//! struct Bar<'a> { x: &'a u32 }
//! ```

// TODO:
// 0: cleanup
// 1: finish table API
// 2: return API
// 3. document
// 4. bench

#[cfg(testr)]
mod test {

    fn run_through<T>(item: T)
    where
        T: SyscallArguments<64, 6> + core::fmt::Debug + Clone + Eq,
    {
        let mut encoder: SyscallEncoder<<T as SyscallArguments<64, 6>>::RegisterType, 64, 6> =
            SyscallEncoder::default();
        item.encode(&mut encoder);
        let args = encoder.finish();

        let mut decoder = SyscallDecoder::new(args);
        let item2 = T::decode(&mut decoder).unwrap();
        assert_eq!(item, item2);
    }

    #[test]
    fn test_enum() {
        #[derive(syscall_macros::SyscallEncode, Copy, Debug, Clone, Eq, PartialEq, PartialOrd)]
        enum Foo {
            One,
            Two(u32),
            Three { x: bool },
            Four { x: bool, y: u8 },
            Five(u32, bool),
        }
        let foo = Foo::One;
        run_through(foo);

        let foo = Foo::Two(89);
        run_through(foo);

        let foo = Foo::Three { x: true };
        run_through(foo);

        let foo = Foo::Four { x: true, y: 45 };
        run_through(foo);

        let foo = Foo::Five(120, false);
        run_through(foo);
    }
    #[test]
    fn test_unit() {
        {
            #[derive(syscall_macros::SyscallEncode, Debug, Clone, Eq, PartialEq, PartialOrd)]
            struct Foo;
            let foo = Foo {};
            run_through(foo);
        }

        {
            #[derive(syscall_macros::SyscallEncode, Debug, Clone, Eq, PartialEq, PartialOrd)]
            struct Foo();
            let foo = Foo {};
            run_through(foo);
        }

        {
            #[derive(syscall_macros::SyscallEncode, Debug, Clone, Eq, PartialEq, PartialOrd)]
            struct Foo {}
            let foo = Foo {};
            run_through(foo);
        }
    }

    #[test]
    fn test_basic() {
        #[derive(syscall_macros::SyscallEncode, Debug, Clone, Eq, PartialEq, PartialOrd)]
        struct Foo {
            x: u32,
            y: Option<u32>,
            z: Option<u32>,
        }
        let foo = Foo {
            x: 8,
            y: Some(9),
            z: None,
        };
        run_through(foo);
    }

    #[test]
    fn test_big() {
        #[derive(syscall_macros::SyscallEncode, Debug, Clone, Eq, PartialEq, PartialOrd)]
        struct Bar(u64, u64, u64, u64, u64, u64, u64, u64);

        let bar = Bar(1, 2, 3, 4, 5, 6, 7, 8);
        let bar2 = bar.clone();
        SyscallEncoder::encode_with(bar, |args| {
            let mut decoder = SyscallDecoder::new(args);
            let item2 = Bar::decode(&mut decoder).unwrap();
            assert_eq!(bar2, item2);
        });
    }

    #[test]
    fn test_nameless() {
        #[derive(syscall_macros::SyscallEncode, Debug, Clone, Eq, PartialEq, PartialOrd)]
        struct Bar(u32);

        run_through(Bar(3));
    }

    #[test]
    fn test_refs() {
        let q: u32 = 0;
        #[derive(syscall_macros::SyscallEncode, Debug, Clone, Eq, PartialEq, PartialOrd)]
        struct Bar<'a> {
            x: UserPointer<'a, u32>,
        }
        run_through(Bar {
            x: UserPointer::from(&q),
        });
    }

    #[test]
    fn test_nested() {
        #[derive(syscall_macros::SyscallEncode, Debug, Clone, Eq, PartialEq, PartialOrd)]
        struct Foo {
            x: u32,
            z: bool,
        }
        #[derive(syscall_macros::SyscallEncode, Debug, Clone, Eq, PartialEq, PartialOrd)]
        struct Bar(u32, Foo, bool);

        run_through(Bar(3, Foo { x: 9, z: false }, true));
    }

    #[test]
    fn test_config() {
        use syscall_macros_traits::SyscallArguments;

        #[derive(syscall_macros::SyscallEncode, Debug, Clone, Eq, PartialEq, PartialOrd)]
        struct Foo(u32);

        #[derive(syscall_macros::SyscallEncode, Debug, Clone, Eq, PartialEq, PartialOrd)]
        #[num_regs = 27]
        #[reg_bits = 64]
        struct Bar(u32);

        let mut encoder = syscall_macros_traits::SyscallEncoder::default();
        Foo(0).encode(&mut encoder);

        assert_eq!(
            encoder.bits(),
            env!("SYSCALL_ENCODE_DEFAULT_NR_BITS").parse().unwrap()
        );
        assert_eq!(
            encoder.nr_regs(),
            env!("SYSCALL_ENCODE_DEFAULT_NR_REGS").parse().unwrap()
        );

        let mut encoder = syscall_macros_traits::SyscallEncoder::default();
        Bar(0).encode(&mut encoder);

        assert_eq!(encoder.bits(), 64);
        assert_eq!(encoder.nr_regs(), 27);
    }
}

//#[cfg(test)]
mod test {

    use std::{sync::{Mutex, Arc}, thread::JoinHandle, alloc::Layout};

    use syscall_macros::SyscallEncodable;
    use syscall_macros_traits::{abi::{
        registers_and_stack::{RegisterAndStackData, RegistersAndStackEncoder},
        SyscallAbi, Allocation,
    }, error::SyscallError, table::SyscallTable, api::SyscallApi, syscall_api};
    const NR_REGS: usize = 6;

    type Register = u64;

    type Encoder<'a> = RegistersAndStackEncoder<'a, NullAbi, Register, NR_REGS>;
    type EncodedType = RegisterAndStackData<Register, NR_REGS>;

    type Sender<T> = Arc<Mutex<std::sync::mpsc::Sender<T>>>;
    type Receiver<T> = Arc<Mutex<std::sync::mpsc::Receiver<T>>>;

    struct NullAbi {
        arg_sender: Sender<(Register, EncodedType)>,
        ret_sender: Sender<EncodedType>,
        arg_receiver: Receiver<(Register, EncodedType)>,
        ret_receiver: Receiver<EncodedType>,
    }

    impl NullAbi {
        fn new() -> Self {
            let (args, argr) = std::sync::mpsc::channel();
            let (rets, retr) = std::sync::mpsc::channel();

                let arg_sender= Arc::new(Mutex::new(args));
               let arg_receiver= Arc::new(Mutex::new(argr));
                let ret_sender= Arc::new(Mutex::new(rets));
               let  ret_receiver
               = Arc::new(Mutex::new(retr));          
               let arg_receiver2 = arg_receiver.clone();
               let ret_sender2 = ret_sender.clone();
                Self {
                    arg_sender,
                    ret_sender,
                    arg_receiver,
                    ret_receiver,
            }
        }
    }

    impl SyscallAbi for NullAbi {
        type SyscallArgType = EncodedType;

        type SyscallRetType = EncodedType;

        type SyscallNumType = Register;

        type ArgEncoder<'a> 
        = Encoder<'a>
        where
            Self: 'a;

        type RetEncoder<'a>
        = Encoder<'a>
        where
            Self: 'a;

        fn with_alloc<F, R, E: Copy>(
            &self,
            layout: std::alloc::Layout,
            f: F,
        ) -> Result<R, SyscallError<E>>
        where
            F: FnOnce(Allocation) -> Result<R, SyscallError<E>>,
        {
            ::alloca::with_alloca_zeroed(layout.size(), |mem| {
                f(Allocation::from(mem))
            })
        }

        fn kernel_alloc(&self, layout: std::alloc::Layout) -> Allocation {
            Allocation::null()
        }

        unsafe fn syscall_impl(
            &self,
            num: Self::SyscallNumType,
            args: Self::SyscallArgType,
        ) -> Self::SyscallRetType {
            self.arg_sender.lock().unwrap().send((num, args)).unwrap();
            self.ret_receiver.lock().unwrap().recv().unwrap()
        }
    }


    struct NullHandler {
        abi: Arc<NullAbi>
    }
    
        impl<'a>             SyscallTable<NullAbi> for NullHandler

        {
            fn handle_call(
                &self,
                num: Register,
                arg: EncodedType,
            ) -> EncodedType {
                let x = unsafe {
                    syscall_api! {
                        num, arg,
                        NullAbi,
                        &*self.abi,
                        (Foo, |_n, _foo| {
                            println!("::: HERE {:?}", _foo);
                            Ok(FooRet {
                            })
                        })
                    }
                };


                println!(":: {:?}", x);
                x
            }
        }


        
        #[derive(SyscallEncodable, Clone, Copy, Debug)]
        struct Foo {
            x: u8,
            y: u8,
        }

        impl<'a> SyscallApi<'a, NullAbi> for Foo {
            type ReturnType = FooRet;

            const NUM: Register = 1;

            type ErrorType = SimpleErr;
        }

        #[derive(SyscallEncodable, Clone, Copy, Debug, PartialEq)]
        struct FooRet;

        #[derive(SyscallEncodable, Clone, Copy, Debug)]
        enum SimpleErr {
            Sad,
        }    


        
        #[test]
    fn basic() {

        let abi = Arc::new(NullAbi::new());
        let abi2 = abi.clone();
        let arg_receiver2 = abi.arg_receiver.clone();
        let ret_sender2 = abi.ret_sender.clone();

        let thr = std::thread::spawn(move || {
                let (num, args) = arg_receiver2.lock().unwrap().recv().unwrap();

                let handler = NullHandler { abi: abi2  };
            let ret = <NullHandler as SyscallTable<NullAbi>>::handle_call(
                &handler, num, args,
            );
            handler.abi.ret_sender.lock().unwrap().send(ret).unwrap();            
           });        

        let foo = Foo { x: 11, y: 33 };
        let res = foo.perform_call(&abi).unwrap();
        assert_eq!(res, FooRet);
        
           }
}
