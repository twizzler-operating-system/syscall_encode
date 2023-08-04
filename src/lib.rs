//!
//! # Pointers and References
//! ```compile_fail
//! #[derive(syscall_macros::SyscallEncode, Debug, Clone, Eq, PartialEq, PartialOrd)]
//! struct Bar<'a> { x: &'a u32 }
//! ```

use syscall_macros::SyscallEncode;
use syscall_macros_traits::{table::SyscallApi, SyscallArgs};

#[cfg(test)]
mod test {
    use syscall_macros_traits::{SyscallArguments, SyscallDecoder, SyscallEncoder, UserPointer};

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

pub fn api(num: u64, args: SyscallArgs<u64, 6>) {
    #[derive(SyscallEncode)]
    struct Foo;
    impl SyscallApi<u64> for Foo {
        const NUM: u64 = 1;
    }

    let _res =
        unsafe { syscall_macros_traits::syscall_api!(num, args, 64, 6, u64, (Foo, |_x, _y| {})) };
}
