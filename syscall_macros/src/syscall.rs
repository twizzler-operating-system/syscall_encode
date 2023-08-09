use proc_macro2::{Ident, Span, TokenStream};
use quote::{quote, spanned::Spanned};
use syn::{DataEnum, DataStruct, DeriveInput, Type, Generics, LifetimeParam, Lifetime, TypeParam, TypeParamBound, TraitBound, parse_quote};

/* 
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
*/

fn check_ty_allowed(span: Span, ty: &Type) -> Result<(), syn::Error> {
    match ty {
        Type::Ptr(_) => Err(syn::Error::new(span, "cannot encode a raw pointer into syscall registers. Use a UserPointer instead.")),
        Type::Reference(_) => Err(syn::Error::new(span, "cannot encode a reference into syscall registers. Use a UserPointer instead.")),
        Type::Slice(_) => Err(syn::Error::new(span, "cannot encode a non-constant size slice into syscall registers.")),
        Type::TraitObject(_) => Err(syn::Error::new(span, "cannot encode a trait object into syscall registers.")),     
        Type::ImplTrait(_) => Err(syn::Error::new(span, "cannot encode an impl trait into syscall registers.")),
        Type::Infer(_) => Err(syn::Error::new(span, "cannot encode an inferred type into syscall registers.")),
        Type::Macro(_) => Err(syn::Error::new(span, "macros are not supported in SyscallArguments deriving.")),
        Type::Never(_) => Err(syn::Error::new(span, "what part of 'never' was unclear?")),
        Type::Verbatim(_) => {Ok(())},
        Type::BareFn(_) => Err(syn::Error::new(span, "cannot encode a bare function into syscall registers.")),           
        _ => {Ok(())},
    }
}

pub fn derive_proc_macro_impl(input: DeriveInput) -> Result<TokenStream, syn::Error> {
    let span = input.__span();
    let DeriveInput {
        ident: struct_name_ident,
        data,
        mut generics,
        attrs,
        ..
    } = input;

    let mut has_repr_c = false;
    for attr in attrs {
        if attr.path().is_ident("repr") {
            let repr: Ident = attr.meta.require_list()?.parse_args()?;
            if repr == *"C" {
                has_repr_c = true;
                break;
            }
            return Err(syn::Error::new(repr.span(), "SyscallEncodable requires #[repr(C)]."));
        }
    }

    if !has_repr_c {
        return Err(syn::Error::new(span, "SyscallEncodable requires #[repr(C)]."));
    }

    //let where_clause = &generics.where_clause;
    //let sysinfo = extract_outer_attrs(span, attrs)?;

    //let required_trait_bounds = vec!["core::default::Default", "core::fmt::Debug"];
    let streams = match &data {
        syn::Data::Struct(st) => handle_struct(span, st),
        syn::Data::Enum(en) => handle_enum(span, struct_name_ident.clone(), en),
        syn::Data::Union(_) => todo!(),
    }?;

    let encode_stream = streams.0;
    let decode_stream = streams.1;

    use syn::spanned::Spanned;
    let struct_generics = generics.clone();

    
    let abi_life = Lifetime::new("'abi", generics.span());      
    let abi_gt: TypeParam = Ident::new("Abi", generics.span()).into();    
    let syscall_abi_tb: TraitBound = parse_quote!(::syscall_encode_traits::abi::SyscallAbi);
    let mut abi_gtb = abi_gt.clone();
    let encoder_gtb: TypeParam = parse_quote!(Encoder: ::syscall_encode_traits::encoder::SyscallEncoder<'abi, Abi, EncodedType> + ::syscall_encode_traits::api::impls::EncodeAllPrimitives<'abi, Abi, EncodedType, Encoder>);
    let encoder_gt: TypeParam = parse_quote!(Encoder);
    let encoded_type_gtb: TypeParam = parse_quote!(EncodedType: Copy);
    let encoded_type_gt: TypeParam = parse_quote!(EncodedType);

    abi_gtb.bounds.push(TypeParamBound::Lifetime(abi_life.clone()));
    abi_gtb.bounds.push(TypeParamBound::Trait(syscall_abi_tb));

    let abi_gt = syn::GenericParam::Type(abi_gt);

    let mut ty_generics = Generics::default();
    
    ty_generics.params.push(abi_gt);
    generics.params.push(syn::GenericParam::Type(abi_gtb));

    ty_generics.params.push(syn::GenericParam::Lifetime(LifetimeParam::new(abi_life.clone())));
    generics.params.push(syn::GenericParam::Lifetime(LifetimeParam::new(abi_life.clone())));

    generics.params.push(encoded_type_gtb.into());
    ty_generics.params.push(encoded_type_gt.into());

    generics.params.push(encoder_gtb.into());
    ty_generics.params.push(encoder_gt.into());
    
    for g in generics.lifetimes_mut() {
        if g.lifetime.to_string() != "'abi" {
            g.bounds.push(abi_life.clone());
        }
    }
    
    let lives: Vec<_> = generics.lifetimes_mut().filter_map(|item| {
        if item.lifetime.to_string() != "'abi" {
            Some(item.lifetime.clone())
        } else {None}
    }).collect();
        
    for g in generics.lifetimes_mut() {
        if g.lifetime.to_string() == "'abi" {
            for l in lives.into_iter() {
                g.bounds.push(l);
            }
            break;
        }
    }

    let (impl_generics, _, where_clause) = generics.split_for_impl();
    
    let (_, s_ty_generics, _) = struct_generics.split_for_impl();

    Ok(quote! {
        impl #impl_generics ::syscall_encode_traits::api::SyscallEncodable #ty_generics for #struct_name_ident #s_ty_generics #where_clause {
            fn encode(&self, encoder: &mut Encoder) -> Result<(), ::syscall_encode_traits::encoder::EncodeError> {
                encoder.size_hint(core::mem::size_of::<Self>());
                #encode_stream
            }

            fn decode(decoder: &mut Encoder) -> Result<Self, ::syscall_encode_traits::encoder::DecodeError> where Self: Sized {
                #decode_stream
            }
        }
    })
}

fn handle_enum(
    _span: Span,
    ident: Ident,
    en: &DataEnum,
) -> syn::Result<(TokenStream, TokenStream)> {
    for var in &en.variants {
        for f in &var.fields {
            check_ty_allowed(f.ty.__span(), &f.ty)?;
        }
    } 
               
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
                        #name.encode(encoder)?;
                    }
                });
                //let disc = quote!(core::mem::discriminant(self).encode(encoder););
                let disc = quote! {
                    {let disc: u64 = #num; disc.encode(encoder)?;}
                };
                quote! {
                    Self::#name #structure => {#disc #(#code)*}
                }
            })
            .collect();
        if internal.is_empty() {
            quote! {Ok(())}
        } else {        quote! {match self {#(#internal)*}; Ok(())}
    }
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
                                let #name = <#ty as ::syscall_encode_traits::api::SyscallEncodable<'abi, Abi, EncodedType, Encoder>>::decode(decoder)?;                            
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
                                let #name = <#ty as ::syscall_encode_traits::api::SyscallEncodable<'abi, Abi, EncodedType, Encoder>>::decode(decoder)?;                            
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
        if internal.is_empty() {
            quote!{Ok(#ident)}
        } else {
                    quote! {
            let disc = u64::decode(decoder)?;
            Ok(match disc {
                #(#internal)*
                _ => return Err(::syscall_encode_traits::encoder::DecodeError::InvalidData)
            })
        }
    }
    };

    Ok((encode, decode))
}

fn handle_struct(_span: Span, st: &DataStruct) -> syn::Result<(TokenStream, TokenStream)> {
    for f in &st.fields {
        check_ty_allowed(f.ty.__span(), &f.ty)?;
    }
    //let SyscallInfo { reg_bits, regs } = info.clone();
    let mut encode:Vec<_> = st
        .fields
        .iter()
        .enumerate()
        .map(|(num, field)| {
            let num = syn::Index::from(num);
            match field.ident.as_ref() {
                Some(name) => {
                    quote! {
                        self.#name.encode(encoder)?;
                    }
                }
                None => quote! {
                    self.#num.encode(encoder)?;
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
                    quote! {#name : <#ty as ::syscall_encode_traits::api::SyscallEncodable<'abi, Abi, EncodedType, Encoder>>::decode(decoder)?}
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
                    quote! {<#ty as ::syscall_encode_traits::api::SyscallEncodable<'abi, Abi, EncodedType, Encoder>>::decode(decoder)?}
                })
                .collect();
            quote! {Ok(Self(#(#internal),*))}
        }
        syn::Fields::Unit => {
            quote! {Ok(Self{})}
        }
    };
    encode.push(quote!(Ok(())));
    let encode = encode.iter().cloned().collect();

    Ok((encode, decode))
}
