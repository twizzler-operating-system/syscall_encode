use std::{fmt::Debug, ops::BitXor};

use crate::{
    api::{impls::EncodeAllPrimitives, SyscallEncodable},
    encoder::{DecodeError, EncodeError, EncodePrimitive, SyscallEncoder},
};

use super::{Allocation, SyscallAbi};

pub struct RegistersAndStackEncoder<
    'a,
    Abi: SyscallAbi,
    RegisterType: Copy + Default,
    const NR_REGS: usize,
> {
    abi: &'a Abi,
    idx: usize,
    by: usize,
    regs: RegisterAndStackData<RegisterType, NR_REGS>,
    alloc: Allocation,
}

pub trait AllowedRegisterType: Into<u128> + BitXor<Output = Self> + TryFrom<u128> + Debug {}

impl AllowedRegisterType for u64 {}

impl<'a, Abi: SyscallAbi, RegisterType: Copy + Default, const NR_REGS: usize>
    RegistersAndStackEncoder<'a, Abi, RegisterType, NR_REGS>
{
    const REG_BYTES: usize = core::mem::size_of::<RegisterType>();
}

impl<'a, Abi: SyscallAbi, RegisterType: Copy + Default, const NR_REGS: usize>
    SyscallEncoder<'a, Abi, RegisterAndStackData<RegisterType, NR_REGS>>
    for RegistersAndStackEncoder<'a, Abi, RegisterType, NR_REGS>
where
    RegisterType: AllowedRegisterType,
{
    fn new_decode(abi: &'a Abi, decode_data: RegisterAndStackData<RegisterType, NR_REGS>) -> Self {
        Self {
            abi,
            regs: decode_data,
            idx: 0,
            alloc: Allocation::null(),
            by: 0,
        }
    }

    fn new_encode(abi: &'a Abi, allocation: Allocation) -> Self {
        Self {
            abi,
            regs: Default::default(),
            idx: 0,
            alloc: allocation,
            by: 0,
        }
    }

    fn encode<
        Source: SyscallEncodable<'a, Abi, RegisterAndStackData<RegisterType, NR_REGS>, Self>,
    >(
        &mut self,
        item: &Source,
    ) -> Result<(), EncodeError> {
        item.encode(self)
    }

    fn finish(self) -> RegisterAndStackData<RegisterType, NR_REGS> {
        self.regs
    }

    fn decode<
        Target: SyscallEncodable<'a, Abi, RegisterAndStackData<RegisterType, NR_REGS>, Self>,
    >(
        &mut self,
    ) -> Result<Target, crate::encoder::DecodeError>
    where
        Self: Sized,
    {
        Target::decode(self)
    }

    fn encode_u8(&mut self, item: u8) -> Result<(), EncodeError>
    where
        Self: Sized,
    {
        if self.idx < NR_REGS - 2 {
            let reg = &mut self.regs.regs[self.idx];

            let maskb = (1u128 << (self.by * 8)).checked_sub(1).unwrap_or_default();
            let maskt = (1u128 << ((self.by + 1) * 8)) - 1;
            let mask = maskt ^ maskb;
            let item = (item as u128) << (self.by * 8);
            let cur_reg: u128 = (*reg).into();

            *reg = ((item & mask) | (cur_reg & !mask))
                .try_into()
                .map_err(|_| EncodeError::PrimitiveError)?;

            self.by += 1;
            if self.by >= Self::REG_BYTES {
                self.idx += 1;
                self.by = 0;
            }
        } else {
            if self.by == 0 {
                self.by = 0xff;
                let ptr = u128::try_from(self.alloc.data as usize)
                    .map_err(|_| EncodeError::PrimitiveError)?;
                self.regs.regs[self.idx] =
                    ptr.try_into().map_err(|_| EncodeError::PrimitiveError)?;
            }
            let space = self
                .alloc
                .reserve::<u8>()
                .ok_or(EncodeError::AllocationError)?;
            *space = item;
        }
        Ok(())
    }

    fn decode_u8(&mut self) -> Result<u8, DecodeError>
    where
        Self: Sized,
    {
        if self.idx < NR_REGS - 2 {
            let reg: u128 = self.regs.regs[self.idx].into();
            let item = reg >> (self.by as u128 * 8);
            let item = (item & 0xff) as u8;
            self.by += 1;
            if self.by >= Self::REG_BYTES {
                self.idx += 1;
                self.by = 0;
            }
            Ok(item)
        } else {
            let reg: u128 = self.regs.regs[self.idx].into();
            let base_ptr = reg as usize as *mut u8;
            let item_ptr = unsafe { base_ptr.add(self.by) };
            self.by += 1;
            Ok(unsafe { *item_ptr })
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct RegisterAndStackData<RegisterType: Copy + Default, const NR_REGS: usize> {
    regs: [RegisterType; NR_REGS],
}

impl<R: Copy + Default, const NR_REGS: usize> Default for RegisterAndStackData<R, NR_REGS> {
    fn default() -> Self {
        Self {
            regs: [R::default(); NR_REGS],
        }
    }
}

/*
impl<'a, Abi: SyscallAbi, RegisterType: Copy + Default, const NR_REGS: usize, Primitive: Copy>
    EncodePrimitive<'a, Abi, RegisterAndStackData<RegisterType, NR_REGS>, Primitive>
    for RegistersAndStackEncoder<'a, Abi, RegisterType, NR_REGS>
where
    Primitive: TryInto<RegisterType>,
    Primitive: TryFrom<RegisterType>,
    RegisterType: From<u8>,
    RegisterType: TryInto<u8>,
{
    fn encode_primitive(&mut self, item: Primitive) -> Result<(), EncodeError> {
        self.regs.regs[self.idx] = item.try_into().map_err(|_| EncodeError::PrimitiveError)?;
        self.idx += 1;
        Ok(())
    }

    fn decode_primitive(&mut self) -> Result<Primitive, crate::encoder::DecodeError> {
        let p = <Primitive as TryFrom<RegisterType>>::try_from(self.regs.regs[self.idx]);
        let p: Primitive = p.map_err(|_| DecodeError::InvalidData)?;
        self.idx += 1;
        Ok(p)
    }
}
*/

impl<'a, Abi: SyscallAbi, RegisterType: Copy + Default, const NR_REGS: usize>
    EncodeAllPrimitives<'a, Abi, RegisterAndStackData<RegisterType, NR_REGS>, Self>
    for RegistersAndStackEncoder<'a, Abi, RegisterType, NR_REGS>
where
    RegisterType: AllowedRegisterType,
{
}
