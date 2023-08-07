use std::alloc::Layout;

use crate::abi::{
    registers_and_stack::{RegisterAndStackData, RegistersAndStackEncoder},
    Allocation, SyscallAbi,
};

type Encoder<'a> = RegistersAndStackEncoder<'a, X86Abi, u64, 6>;
type EncodedType = RegisterAndStackData<u64, 6>;

struct X86Abi;

impl SyscallAbi for X86Abi {
    type SyscallArgType = EncodedType;

    type SyscallRetType = EncodedType;

    type SyscallNumType = u64;

    type ArgEncoder<'a> = Encoder<'a>
        where
            Self: 'a;

    type RetEncoder<'a> = Encoder<'a>
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

    unsafe fn syscall_impl(
        &self,
        num: Self::SyscallNumType,
        args: Self::SyscallArgType,
    ) -> Self::SyscallRetType {
        todo!()
    }
}
