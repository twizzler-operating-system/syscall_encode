use proc_macro2::{Ident, Span, TokenStream};
use quote::{quote, spanned::Spanned};
use syn::{Attribute, DataEnum, DataStruct, DeriveInput, Error, Type};

struct SyscallInfo {
    regs: usize,
    reg_bits: usize,
}

const DEFAULT_NR_REGS: Option<&'static str> = option_env!("SYSCALL_ENCODE_DEFAULT_NR_REGS");
const DEFAULT_NR_BITS: Option<&'static str> = option_env!("SYSCALL_ENCODE_DEFAULT_NR_BITS");

fn default_nr_regs() -> Option<usize> {
    DEFAULT_NR_REGS.map(|s| s.parse().ok()).flatten()
}

fn default_nr_bits() -> Option<usize> {
    DEFAULT_NR_BITS.map(|s| s.parse().ok()).flatten()
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
    if regs.is_none() {
        regs = default_nr_regs();
    }

    if reg_bits.is_none() {
        reg_bits = default_nr_bits();
    }
    Ok(SyscallInfo {
        regs: regs.ok_or(Error::new(
            fullspan,
            "derive macro SyscallEncode requires attribute 'num_regs' or a default value specified via environment".to_string(),
        ))?,
        reg_bits: reg_bits.ok_or(Error::new(
            fullspan,
            "derive macro SyscallEncode requires attribute 'reg_bits' or a default value specified via environment".to_string(),
        ))?,
    })
}

fn check_ty_allowed(span: Span, ty: &Type) -> Result<(), syn::Error> {
    match ty {
        Type::Ptr(_) => return Err(syn::Error::new(span, "cannot encode a raw pointer into syscall registers. Use a UserPointer instead.")),
        Type::Reference(_) => return Err(syn::Error::new(span, "cannot encode a reference into syscall registers. Use a UserPointer instead.")),
        Type::Slice(_) => return Err(syn::Error::new(span, "cannot encode a non-constant size slice into syscall registers.")),
        Type::TraitObject(_) => return Err(syn::Error::new(span, "cannot encode a trait object into syscall registers.")),     
        Type::ImplTrait(_) => return Err(syn::Error::new(span, "cannot encode an impl trait into syscall registers.")),
        Type::Infer(_) => return Err(syn::Error::new(span, "cannot encode an inferred type into syscall registers.")),
        Type::Macro(_) => return Err(syn::Error::new(span, "macros are not supported in SyscallArguments deriving.")),
        Type::Never(_) => return Err(syn::Error::new(span, "what part of 'never' was unclear?")),
        Type::Verbatim(_) => {Ok(())},
        Type::BareFn(_) => return Err(syn::Error::new(span, "cannot encode a bare function into syscall registers.")),           
        _ => {Ok(())},
    }
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
    let streams = match &data {
        syn::Data::Struct(st) => handle_struct(span, st, &sysinfo),
        syn::Data::Enum(en) => handle_enum(span, en, &sysinfo),
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

fn handle_enum(
    _span: Span,
    en: &DataEnum,
    info: &SyscallInfo,
) -> syn::Result<(TokenStream, TokenStream)> {
    for var in &en.variants {
        for f in &var.fields {
            check_ty_allowed(f.ty.__span(), &f.ty)?;
        }
    } 
               
    let SyscallInfo { regs, reg_bits } = info;
    let encode = {
        let internal: Vec<_> = en
            .variants
            .iter()
            .enumerate()
            .map(|(num, var)| {
                let num = num as u64;
                let name = &var.ident;

                let (names, structure) = match &var.fields {
                    syn::Fields::Named(fields) => {
                        let names: Vec<_> = fields
                            .named
                            .iter()
                            .map(|field| field.ident.as_ref().unwrap().clone())
                            .collect();
                        (names.clone(), quote!({#(#names),*}))
                    }
                    syn::Fields::Unnamed(fields) => {
                        let names: Vec<_> = fields
                            .unnamed
                            .iter()
                            .enumerate()
                            .map(|(num, field)| {
                                let s = format!("x{}", num);
                                Ident::new(s.as_str(), field.__span())
                            })
                            .collect();
                        (names.clone(), quote!((#(#names),*)))
                    }
                    syn::Fields::Unit => (Vec::new(), quote!()),
                };

                let code = names.iter().map(|name| {
                    quote! {
                        #name.encode(encoder);
                    }
                });
                //let disc = quote!(core::mem::discriminant(self).encode(encoder););
                let disc = quote! {
                    {let disc: u64 = #num; disc.encode(encoder);}
                };
                quote! {
                    Self::#name #structure => {#disc #(#code)*}
                }
            })
            .collect();
        quote! {match self {#(#internal)*}}
    };

    let decode = {
        let internal: Vec<_> = en
            .variants
            .iter()
            .enumerate()
            .map(|(num, var)| {
                let num = num as u64;
                let name = &var.ident;

                let (_names, structure, code) = match &var.fields {
                    syn::Fields::Named(fields) => {
                        let names: Vec<_> = fields
                            .named
                            .iter()
                            .map(|field| field.ident.as_ref().unwrap().clone())
                            .collect();
                        let code: Vec<_> = fields.named.iter().map(|field| {
                            let name = field.ident.as_ref().unwrap();
                            let ty = &field.ty;
                            quote!{
                                let #name = <#ty as ::syscall_macros_traits::SyscallArguments<#reg_bits, #regs>>::decode(decoder)?;                            
                            }
                        }).collect();
                        (names.clone(), quote!({#(#names),*}), code)
                    }
                    syn::Fields::Unnamed(fields) => {
                        let names: Vec<_> = fields
                            .unnamed
                            .iter()
                            .enumerate()
                            .map(|(num, field)| {
                                let s = format!("x{}", num);
                                Ident::new(s.as_str(), field.__span())
                            })
                            .collect();
                        
                        let code: Vec<_> = fields.unnamed.iter().zip(names.iter()).map(|(field, ident)| {
                            let name = ident;
                            let ty = &field.ty;
                            quote!{
                                let #name = <#ty as ::syscall_macros_traits::SyscallArguments<#reg_bits, #regs>>::decode(decoder)?;                            
                            }
                        }).collect();                       
                        (names.clone(), quote!((#(#names),*)), code)
                    }
                    syn::Fields::Unit => (Vec::new(), quote!(), Vec::new()),
                };
                quote! {
                    #num => {
                        #(#code);*
                        Self::#name #structure
                    }
                }
            })
            .collect();
        quote! {
            let disc = u64::decode(decoder)?;
            Ok(match disc {
                #(#internal)*
                _ => return Err(::syscall_macros_traits::DecodeError::InvalidData)
            })
        }
    };

    Ok((encode, decode))
}

fn handle_struct(_span: Span, st: &DataStruct, info: &SyscallInfo) -> syn::Result<(TokenStream, TokenStream)> {
    for f in &st.fields {
        check_ty_allowed(f.ty.__span(), &f.ty)?;
    }
    let SyscallInfo { reg_bits, regs } = info.clone();
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
                    quote! {#name : <#ty as ::syscall_macros_traits::SyscallArguments<#reg_bits, #regs>>::decode(decoder)?}
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
                    quote! {<#ty as ::syscall_macros_traits::SyscallArguments<#reg_bits, #regs>>::decode(decoder)?}
                })
                .collect();
            quote! {Ok(Self(#(#internal),*))}
        }
        syn::Fields::Unit => {
            quote! {Ok(Self{})}
        }
    };

    Ok((encode, decode))
}
