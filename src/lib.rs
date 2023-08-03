// TODO
// 1: enums, unit structs
// 2. nesting
// 3. pointers

//#[cfg(test)]
mod test {
    #[derive(syscall_macros::SyscallEncode, Debug, Clone, Eq, PartialEq, PartialOrd)]
    struct Foo {
        x: u32,
        y: u32,
        z: Option<u32>,
        a: Option<u32>,
    }

    #[test]
    fn foo() {
        use syscall_macros_traits::SyscallArgs;
        use syscall_macros_traits::SyscallArguments;

        let foo = Foo {
            x: 8,
            y: 9,
            z: None,
            a: Some(42),
        };
        // step 1: encode Foo into registers
        let mut encoder = syscall_macros_traits::SyscallEncoder::default();
        foo.encode(&mut encoder);
        let args: SyscallArgs<u64, 6> = encoder.finish();

        // 'args' can be passed to raw_syscall

        // decode back into a Foo.
        let mut decoder = syscall_macros_traits::SyscallDecoder::new(args);
        let foo2 = Foo::decode(&mut decoder).unwrap();

        assert_eq!(foo, foo2);
    }

    #[test]
    fn test_nameless() {
        use syscall_macros_traits::SyscallArgs;
        use syscall_macros_traits::SyscallArguments;
        #[derive(syscall_macros::SyscallEncode, Debug, Clone, Eq, PartialEq, PartialOrd)]
        #[num_regs = 6]
        #[reg_bits = 64]
        struct Bar(u32);

        let bar = Bar(42);
        // step 1: encode Foo into registers
        let mut encoder = syscall_macros_traits::SyscallEncoder::default();
        bar.encode(&mut encoder);
        let args: SyscallArgs<u64, 6> = encoder.finish();

        // 'args' can be passed to raw_syscall

        // decode back into a Foo.
        let mut decoder = syscall_macros_traits::SyscallDecoder::new(args);
        let bar2 = Bar::decode(&mut decoder).unwrap();

        assert_eq!(bar, bar2);
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
