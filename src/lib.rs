/*
impl Foo {
    fn serialize(&self) -> SyscallArgs<u64, 6> {
        SyscallArgs {
            regs: [self.x.into(), self.y.into(), 0, 0, 0, 0],
            extra_data: None,
        }
    }

    fn deserialize(args: SyscallArgs<u64, 6>) -> Result<Self, DeserializeError> {
        Ok(Self {
            x: args.regs[0]
                .try_into()
                .map_err(|e| DeserializeError::TryFromIntError(e))?,
            y: args.regs[0]
                .try_into()
                .map_err(|e| DeserializeError::TryFromIntError(e))?,
        })
    }
}
*/

#[derive(syscall_macros::SyscallSerialize, Debug, Clone, Eq, PartialEq, PartialOrd)]
#[num_regs = 6]
#[reg_bits = 64]
struct Foo {
    x: u32,
    y: u32,
}

#[test]
fn foo() {
    use syscall_macros_traits::SyscallArgs;
    use syscall_macros_traits::SyscallArguments;

    let foo = Foo { x: 8, y: 9 };
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
    #[derive(syscall_macros::SyscallSerialize, Debug, Clone, Eq, PartialEq, PartialOrd)]
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
