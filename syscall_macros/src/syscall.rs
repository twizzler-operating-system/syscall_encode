use proc_macro2::{Span, TokenStream};
use quote::{quote, spanned::Spanned};
use syn::{Attribute, DataStruct, DeriveInput, Error};

struct SyscallInfo {
    regs: usize,
    reg_bits: usize,
}

fn extract_outer_attrs(fullspan: Span, attrs: Vec<Attribute>) -> syn::Result<SyscallInfo> {
    let mut regs = None;
    let mut reg_bits = None;
    for attr in attrs {
        let name = &attr
            .path()
            .segments
            .last()
            .expect("empty path for attribute")
            .ident;
        let value = match &attr.meta.require_name_value()?.value {
            syn::Expr::Lit(lit) => match &lit.lit {
                syn::Lit::Int(i) => i.base10_parse::<usize>()?,
                _ => {
                    return Err(Error::new(
                        attr.__span(),
                        format!(
                        "failed to parse {} attribute value -- only literal integers are supported",
                        name
                    ),
                    ))
                }
            },
            _ => {
                return Err(Error::new(
                    attr.__span(),
                    format!(
                        "failed to parse {} attribute value -- only literal integers are supported",
                        name
                    ),
                ))
            }
        };

        match name.to_string().as_str() {
            "num_regs" => regs = Some(value),
            "reg_bits" => reg_bits = Some(value),
            _ => {
                return Err(Error::new(
                    attr.__span(),
                    format!("unknown attribute {}", name),
                ))
            }
        }
    }
    Ok(SyscallInfo {
        regs: regs.ok_or(Error::new(
            fullspan,
            "derive macro SyscallInfo requires attribute 'num_regs'".to_string(),
        ))?,
        reg_bits: reg_bits.ok_or(Error::new(
            fullspan,
            "derive macro SyscallInfo requires attribute 'reg_type'".to_string(),
        ))?,
    })
}

pub fn derive_proc_macro_impl(input: DeriveInput) -> Result<TokenStream, syn::Error> {
    let span = input.__span();
    let DeriveInput {
        ident: struct_name_ident,
        data,
        generics,
        attrs,
        ..
    } = input;

    let where_clause = &generics.where_clause;
    let sysinfo = extract_outer_attrs(span, attrs)?;

    //let required_trait_bounds = vec!["core::default::Default", "core::fmt::Debug"];
    let streams = match data {
        syn::Data::Struct(st) => handle_struct(&st),
        syn::Data::Enum(_) => todo!(),
        syn::Data::Union(_) => todo!(),
    }?;

    let num_bits = sysinfo.reg_bits;
    let reg_type = match num_bits {
        64 => quote! {u64},
        32 => quote! {u32},
        128 => quote! {u128},
        _ => {
            return Err(Error::new(
                span,
                format!("cannot handle register bitwidth of {}", num_bits),
            ))
        }
    };
    let num_regs = sysinfo.regs;
    let encode_stream = streams.0;
    let decode_stream = streams.1;

    Ok(quote! {
        impl #generics ::syscall_macros_traits::SyscallArguments<#num_bits, #num_regs> for #struct_name_ident #generics #where_clause {
            type RegisterType = #reg_type;
            fn encode(&self, encoder: &mut ::syscall_macros_traits::SyscallEncoder<Self::RegisterType, #num_bits, #num_regs>) {
                #encode_stream
            }

            fn decode(decoder: &mut ::syscall_macros_traits::SyscallDecoder<Self::RegisterType, #num_bits, #num_regs>) -> Result<Self, ::syscall_macros_traits::DecodeError> where Self: Sized {
                #decode_stream
            }
        }
    }
    .into())
}

fn handle_struct(st: &DataStruct) -> syn::Result<(TokenStream, TokenStream)> {
    let encode = st
        .fields
        .iter()
        .enumerate()
        .map(|(num, field)| {
            let num = syn::Index::from(num);
            match field.ident.as_ref() {
                Some(name) => {
                    quote! {
                        self.#name.encode(encoder);
                    }
                }
                None => quote! {
                    self.#num.encode(encoder);
                },
            }
        })
        .collect();

    let decode = match &st.fields {
        syn::Fields::Named(fields) => {
            let internal: Vec<_> = fields
                .named
                .iter()
                .map(|field| {
                    let name = field.ident.as_ref().unwrap();
                    let ty = &field.ty;
                    quote! {#name : #ty::decode(decoder)?}
                })
                .collect();
            quote! {Ok(Self{#(#internal),*})}
        }
        syn::Fields::Unnamed(fields) => {
            let internal: Vec<_> = fields
                .unnamed
                .iter()
                .enumerate()
                .map(|(_num, field)| {
                    let ty = &field.ty;
                    quote! {#ty::decode(decoder)?}
                })
                .collect();
            quote! {Ok(Self(#(#internal),*))}
        }
        syn::Fields::Unit => todo!(),
    };

    Ok((encode, decode))
}
