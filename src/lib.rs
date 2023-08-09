//! # Syscall Encode
//! Type-safe Automatic syscall encoding support.
//!
//! The goal of this crate is to supply mechanisms for OS kernels and ABI libraries to define:
//! 1. Exact syscall ABI semantics, including how arguments are encoded and sent between kernel and userspace: [abi::SyscallAbi].
//! 2. A method for enabling a type to be encoded into what can be sent via a syscall instruction (according to the defined ABI): [api::SyscallEncodable].
//! 3. A method for defining such an encodable type as an API endpoint that allows userspace to easily perform syscalls using a type as arguments [api::SyscallApi].
//! 4. A derive macro that derives the encodable trait [SyscallEncodable].
//! 5. A trait that provides much lower overhead than the normal encoding, but may be harder to use and more limited [api::SyscallFastApi].
//! 6. A way to encode pointers to other userland data structures that the kernel can verify before derefencing.
//!
//!
//! More documentation coming...
//!
//! # Pointers and References
//! You cannot encode a pointer or reference directly. Instead, you can use the UserPointer type, which will encode a
//! reference that is safe to pass to the kernel.
//!
//! ```compile_fail
//! #[derive(syscall_macros::SyscallEncodable, Debug, Clone, Eq, PartialEq, PartialOrd)]
//! struct Bar<'a> { x: &'a u32 }
//! ```

#![allow(soft_unstable)]
#![feature(test)]
extern crate test;

pub use syscall_encode_macros::SyscallEncodable;
pub use syscall_encode_traits::*;

pub mod tests {
    use std::{
        fmt::Debug,
        sync::{Arc, Mutex},
    };

    #[cfg(all(not(miri), test))]
    use std::mem::size_of;

    #[cfg(test)]
    use rand::random;
    use syscall_encode_macros::SyscallEncodable;
    use syscall_encode_traits::{
        abi::{
            registers_and_stack::{RegisterAndStackData, RegistersAndStackEncoder},
            Allocation, SyscallAbi,
        },
        api::{SyscallApi, SyscallEncodable, SyscallFastApi},
        encoder::SyscallEncoder,
        error::SyscallError,
        ptr::{UserPointer, UserSlice},
        syscall_api,
        table::SyscallTable,
    };
    const NR_REGS: usize = 6;

    type Register = u64;

    type Encoder<'a> = RegistersAndStackEncoder<'a, NullAbi, Register, NR_REGS>;
    type EncodedType = RegisterAndStackData<Register, NR_REGS>;

    type Sender<T> = Arc<Mutex<std::sync::mpsc::Sender<T>>>;
    type Receiver<T> = Arc<Mutex<std::sync::mpsc::Receiver<T>>>;

    #[allow(dead_code)]
    pub struct NullAbi {
        arg_sender: Sender<(Register, EncodedType)>,
        ret_sender: Sender<EncodedType>,
        arg_receiver: Receiver<(Register, EncodedType)>,
        ret_receiver: Receiver<EncodedType>,
    }

    impl Default for NullAbi {
        fn default() -> Self {
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
            #[cfg(miri)]
            {
                let mut region = Box::new([0u8; 256]);
                let ptr = &mut *region as *mut [u8; 256];
                let _off = ptr.align_offset(layout.align());

                let _off = 0;
                let size = 256 - _off;
                if size < layout.size() {
                    return Err(SyscallError::AllocationError);
                }
                f(Allocation::from(&mut region[_off..(_off + size)]))
            }
            #[cfg(not(miri))]
            {
                ::alloca::with_alloca_zeroed(layout.size(), |mem| f(Allocation::from(mem)))
            }
        }

        unsafe fn kernel_alloc(&self, _layout: std::alloc::Layout) -> Allocation {
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

        fn unrecoverable_encoding_failure<
            'a,
            EncodedType: Copy,
            Encoder: SyscallEncoder<'a, Self, EncodedType>,
            T: SyscallEncodable<'a, Self, EncodedType, Encoder>,
        >(
            &self,
            _item: T,
        ) {
            panic!("unrecoverable encoding failure")
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
    pub struct Foo {
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

    #[derive(SyscallEncodable, Clone, Copy, Debug, PartialEq, Eq)]
    #[repr(C)]
    pub struct PtrTest<'a> {
        ptr: UserPointer<'a, u32>,
    }

    #[derive(SyscallEncodable, Clone, Copy, Debug, PartialEq, Eq)]
    #[repr(C)]
    pub struct SliceTest<'a> {
        ptr: UserSlice<'a, u32>,
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
    pub enum FooOpts {
        A,
        B(u32, bool),
        C { x: u32, y: u16 },
    }

    #[derive(SyscallEncodable, Clone, Copy, Debug, PartialEq, Eq)]
    #[repr(C)]
    pub struct FooOpts2(u16, bool);

    #[derive(SyscallEncodable, Clone, Copy, Debug, PartialEq, Eq)]
    #[repr(C)]
    pub struct Unit;

    impl<'a> SyscallApi<'a, NullAbi> for Foo {
        type ReturnType = FooRet;

        const NUM: Register = 1;

        type ErrorType = SimpleErr;
    }

    #[derive(SyscallEncodable, Clone, Copy, Debug, PartialEq)]
    #[repr(C)]
    pub struct FooRet;

    #[derive(SyscallEncodable, Clone, Copy, Debug)]
    #[repr(C)]
    pub enum SimpleErr {
        Sad,
    }

    pub fn test_encode<
        'a,
        T: PartialEq + Clone + Copy + Debug + SyscallEncodable<'a, NullAbi, EncodedType, Encoder<'a>>,
    >(
        abi: &'a Arc<NullAbi>,
        item: T,
        more_tests: impl FnOnce(T, T),
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
            more_tests(item, decoded);
            Result::<(), SyscallError<()>>::Ok(())
        })
        .unwrap();
    }

    pub fn test_encode_fast<
        'a,
        T: PartialEq + Clone + Copy + Debug + SyscallFastApi<'a, NullAbi>,
    >(
        _abi: &'a Arc<NullAbi>,
        item: T,
    ) {
        let encoded: EncodedType = item.into();

        core::hint::black_box(encoded);

        let decoded: T = encoded.into();
        assert_eq!(decoded, item);
    }

    #[cfg(test)]
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
    pub struct Bar {
        pub x: u32,
        pub y: u32,
    }
    pub struct Baz {
        a: bool,
    }
    impl From<Bar> for EncodedType {
        fn from(value: Bar) -> Self {
            Self {
                regs: [value.x.into(), value.y.into(), 0, 0, 0, 0],
                #[cfg(miri)]
                ptr: core::ptr::null(),
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

    impl From<Baz> for EncodedType {
        fn from(value: Baz) -> Self {
            Self {
                regs: [value.a.into(), 0, 0, 0, 0, 0],
                #[cfg(miri)]
                ptr: core::ptr::null(),
            }
        }
    }

    impl<'a> SyscallFastApi<'a, NullAbi> for Bar {
        const NUM: u64 = 2;

        type ReturnType = Baz;
    }

    #[test]
    fn full() {
        let abi = Arc::new(NullAbi::default());
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
        let abi = Arc::new(NullAbi::default());

        for _ in 0..100 {
            let foo = Foo::new_random();
            test_encode(&abi, foo, |_, _| {});
        }
    }

    #[cfg(not(miri))]
    #[test]
    fn test_user_pointer() {
        let abi = Arc::new(NullAbi::default());
        let ptr = &8u32;
        let item = PtrTest { ptr: ptr.into() };
        test_encode(&abi, item, |orig, decoded| {
            let o_ref = orig.ptr.as_ref(|_, len| {
                assert_eq!(len, size_of::<u32>());
                true
            });
            let d_ref = decoded.ptr.as_ref(|_, len| {
                assert_eq!(len, size_of::<u32>());
                true
            });
            assert_eq!(o_ref, d_ref);
        });
    }

    #[cfg(not(miri))]
    #[test]
    fn test_user_slice() {
        let abi = Arc::new(NullAbi::default());
        let ptr = (&[8u32]).as_slice();
        let item = SliceTest { ptr: ptr.into() };
        test_encode(&abi, item, |orig, decoded| {
            let o_ref = orig.ptr.as_ref(|_, len| {
                assert_eq!(len, size_of::<u32>() * ptr.len());
                true
            });
            let d_ref = decoded.ptr.as_ref(|_, len| {
                assert_eq!(len, size_of::<u32>() * ptr.len());
                true
            });
            assert_eq!(o_ref, d_ref);
        });
    }

    #[test]
    fn test_fast() {
        let abi = Arc::new(NullAbi::default());

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
}
