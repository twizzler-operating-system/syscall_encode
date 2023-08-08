//!
//! # Pointers and References
//! ```compile_fail
//! #[derive(syscall_macros::SyscallEncodable, Debug, Clone, Eq, PartialEq, PartialOrd)]
//! struct Bar<'a> { x: &'a u32 }
//! ```

// TODO:
// 0: cleanup
// 1: finish table API
// 3. document
// 4. bench

#![allow(soft_unstable)]
#![feature(test)]
extern crate test;

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

#[cfg(test)]
mod tests {
    use std::{
        fmt::Debug,
        process::Termination,
        sync::{Arc, Mutex},
    };

    use rand::random;
    use syscall_macros::SyscallEncodable;
    use syscall_macros_traits::{
        abi::{
            registers_and_stack::{RegisterAndStackData, RegistersAndStackEncoder},
            Allocation, SyscallAbi,
        },
        api::{SyscallApi, SyscallEncodable, SyscallFastApi},
        encoder::SyscallEncoder,
        error::SyscallError,
        syscall_api,
        table::SyscallTable,
    };
    use test::Bencher;
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

            let arg_sender = Arc::new(Mutex::new(args));
            let arg_receiver = Arc::new(Mutex::new(argr));
            let ret_sender = Arc::new(Mutex::new(rets));
            let ret_receiver = Arc::new(Mutex::new(retr));
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

        type ArgEncoder<'a> = Encoder<'a>
        where
            Self: 'a;

        type RetEncoder<'a> = Encoder<'a>
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
            let mut region = Box::new([0u8; 256]);
            let ptr = &mut *region as *mut [u8; 256];
            let _off = ptr.align_offset(layout.align());
            #[cfg(miri)]
            let _off = 0;
            let size = 256 - _off;
            if size < layout.size() {
                return Err(SyscallError::AllocationError);
            }
            f(Allocation::from(&mut region[_off..(_off + size)]))

            //::alloca::with_alloca_zeroed(layout.size(), |mem| f(Allocation::from(mem)))
        }

        fn kernel_alloc(&self, _layout: std::alloc::Layout) -> Allocation {
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
        abi: Arc<NullAbi>,
    }
    impl<'a> SyscallTable<NullAbi> for NullHandler {
        fn handle_call(&self, num: Register, arg: EncodedType) -> EncodedType {
            unsafe {
                syscall_api! {
                    number = num;
                    args = arg;
                    abi_type = NullAbi;
                    abi = &*self.abi;
                    handlers = {
                        (Foo, |_n, _foo| {
                            Ok(FooRet { })
                        })
                    }
                    fast_handlers = {
                        (Bar, |_n, _foo| {
                            Baz { a: false }
                        })
                    }
                }
            }
        }
    }

    #[derive(SyscallEncodable, Clone, Copy, Debug, PartialEq, Eq)]
    #[repr(C)]
    struct Foo {
        x: u16,
        opts1: FooOpts,
        y: u64,
        a: Option<u64>,
        b: u64,
        u: (),
        unit: Unit,
        c: Result<u64, bool>,
        opts: FooOpts,
    }

    impl Default for Foo {
        fn default() -> Self {
            Self {
                x: Default::default(),
                opts1: FooOpts::A,
                y: Default::default(),
                a: Default::default(),
                b: Default::default(),
                u: Default::default(),
                unit: Unit,
                c: Ok(0),
                opts: FooOpts::A,
            }
        }
    }

    #[derive(SyscallEncodable, Clone, Copy, Debug, PartialEq, Eq)]
    #[repr(C)]
    enum FooOpts {
        A,
        B(u32, bool),
        C { x: u32, y: u16 },
    }

    #[derive(SyscallEncodable, Clone, Copy, Debug, PartialEq, Eq)]
    #[repr(C)]
    struct FooOpts2(u16, bool);

    #[derive(SyscallEncodable, Clone, Copy, Debug, PartialEq, Eq)]
    #[repr(C)]
    struct Unit;

    impl<'a> SyscallApi<'a, NullAbi> for Foo {
        type ReturnType = FooRet;

        const NUM: Register = 1;

        type ErrorType = SimpleErr;
    }

    #[derive(SyscallEncodable, Clone, Copy, Debug, PartialEq)]
    #[repr(C)]
    struct FooRet;

    #[derive(SyscallEncodable, Clone, Copy, Debug)]
    #[repr(C)]
    enum SimpleErr {
        Sad,
    }

    #[cfg(test)]
    fn test_encode<
        'a,
        T: PartialEq + Clone + Copy + Debug + SyscallEncodable<'a, NullAbi, EncodedType, Encoder<'a>>,
    >(
        abi: &'a Arc<NullAbi>,
        item: T,
    ) {
        let layout = core::alloc::Layout::new::<T>();
        abi.with_alloc(layout, |alloc| {
            let mut encoder = abi.arg_encoder(alloc);
            item.encode(&mut encoder).unwrap();
            let encoded = encoder.finish();

            core::hint::black_box(encoded);

            let mut decoder = abi.arg_decoder(encoded);
            let decoded = T::decode(&mut decoder).unwrap();
            assert_eq!(decoded, item);
            Result::<(), SyscallError<()>>::Ok(())
        })
        .unwrap();
    }

    #[cfg(test)]
    fn test_encode_fast<'a, T: PartialEq + Clone + Copy + Debug + SyscallFastApi<'a, NullAbi>>(
        abi: &'a Arc<NullAbi>,
        item: T,
    ) {
        let layout = core::alloc::Layout::new::<T>();
        abi.with_alloc(layout, |alloc| {
            let encoded: EncodedType = item.into();

            core::hint::black_box(encoded);

            let decoded: T = encoded.into();
            assert_eq!(decoded, item);
            Result::<(), SyscallError<()>>::Ok(())
        })
        .unwrap();
    }
    impl Foo {
        fn new_random() -> Self {
            Self {
                x: random(),
                opts1: if random() {
                    FooOpts::B(random(), random())
                } else if random() {
                    FooOpts::C {
                        x: random(),
                        y: random(),
                    }
                } else {
                    FooOpts::A
                },
                y: random(),
                u: (),
                a: random(),
                b: random(),
                unit: Unit,
                c: if random() {
                    Ok(random())
                } else {
                    Err(random())
                },
                opts: if random() {
                    FooOpts::B(random(), random())
                } else if random() {
                    FooOpts::C {
                        x: random(),
                        y: random(),
                    }
                } else {
                    FooOpts::A
                },
            }
        }
    }

    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    struct Bar {
        x: u32,
        y: u32,
    }
    struct Baz {
        a: bool,
    }
    impl Into<EncodedType> for Bar {
        fn into(self) -> EncodedType {
            EncodedType {
                regs: [self.x.into(), self.y.into(), 0, 0, 0, 0],
                ..Default::default()
            }
        }
    }
    impl From<EncodedType> for Bar {
        fn from(value: EncodedType) -> Self {
            Self {
                x: value.regs[0] as u32,
                y: value.regs[1] as u32,
            }
        }
    }

    impl From<EncodedType> for Baz {
        fn from(value: EncodedType) -> Self {
            Self {
                a: value.regs[0] != 0,
            }
        }
    }
    impl Into<EncodedType> for Baz {
        fn into(self) -> EncodedType {
            EncodedType {
                regs: [self.a.into(), 0, 0, 0, 0, 0],
                ..Default::default()
            }
        }
    }

    impl<'a> SyscallFastApi<'a, NullAbi> for Bar {
        const NUM: u64 = 2;

        type ReturnType = Baz;
    }

    #[test]
    fn full() {
        let abi = Arc::new(NullAbi::new());
        let abi2 = abi.clone();

        let thr = std::thread::spawn(move || {
            let handler = NullHandler { abi: abi2 };
            let (num, args) = handler.abi.arg_receiver.lock().unwrap().recv().unwrap();

            let ret = <NullHandler as SyscallTable<NullAbi>>::handle_call(&handler, num, args);
            handler.abi.ret_sender.lock().unwrap().send(ret).unwrap();
        });

        let foo = Foo::new_random();
        let res = foo.perform_call(&abi).unwrap();
        assert_eq!(res, FooRet);
        thr.join().unwrap();
    }

    #[test]
    fn encoding() {
        let abi = Arc::new(NullAbi::new());

        for _ in 0..100 {
            let foo = Foo::new_random();
            test_encode(&abi, foo);
        }
    }

    #[test]
    fn test_fast() {
        let abi = Arc::new(NullAbi::new());

        let abi2 = abi.clone();

        let thr = std::thread::spawn(move || {
            let handler = NullHandler { abi: abi2 };
            let (num, args) = handler.abi.arg_receiver.lock().unwrap().recv().unwrap();

            let ret = <NullHandler as SyscallTable<NullAbi>>::handle_call(&handler, num, args);
            handler.abi.ret_sender.lock().unwrap().send(ret).unwrap();
        });
        let bar = Bar { x: 32, y: 1 };

        let _r = bar.perform_call(&*abi);

        thr.join().unwrap();
    }

    #[bench]
    fn bench(bencher: &mut Bencher) -> impl Termination {
        let abi = Arc::new(NullAbi::new());
        bencher.iter(|| {
            for _ in 0..1 {
                let foo = Foo::default();
                test_encode(&abi, foo);
            }
        });
        Ok::<(), ()>(())
    }

    #[bench]
    fn bench_fast(bencher: &mut Bencher) -> impl Termination {
        let abi = Arc::new(NullAbi::new());
        bencher.iter(|| {
            for _ in 0..1 {
                let bar = Bar { x: 3, y: 12 };
                test_encode_fast(&abi, bar);
            }
        });
        Ok::<(), ()>(())
    }
}
