use proc_macro::TokenStream;
use syn::{parse_macro_input, DeriveInput};

mod syscall;
#[proc_macro_derive(SyscallEncodable, attributes(reg_bits, num_regs))]
pub fn syscall_encodable_proc_macro(input: TokenStream) -> TokenStream {
    let derive_input: DeriveInput = parse_macro_input!(input as DeriveInput);
    match syscall::derive_proc_macro_impl(derive_input) {
        Ok(ts) => ts.into(),
        Err(err) => TokenStream::from(err.to_compile_error()),
    }
}
