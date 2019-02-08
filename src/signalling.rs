// This file is generated. Do not edit
// @generated

// https://github.com/Manishearth/rust-clippy/issues/702
#![allow(unknown_lints)]
#![allow(clippy)]

#![cfg_attr(rustfmt, rustfmt_skip)]

#![allow(box_pointers)]
#![allow(dead_code)]
#![allow(missing_docs)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(trivial_casts)]
#![allow(unsafe_code)]
#![allow(unused_imports)]
#![allow(unused_results)]

use protobuf::Message as Message_imported_for_functions;
use protobuf::ProtobufEnum as ProtobufEnum_imported_for_functions;

#[derive(PartialEq,Clone,Default)]
pub struct PubKey {
    // message fields
    key: ::protobuf::SingularField<::std::vec::Vec<u8>>,
    field_type: ::std::option::Option<KeyType>,
    // special fields
    unknown_fields: ::protobuf::UnknownFields,
    cached_size: ::protobuf::CachedSize,
}

// see codegen.rs for the explanation why impl Sync explicitly
unsafe impl ::std::marker::Sync for PubKey {}

impl PubKey {
    pub fn new() -> PubKey {
        ::std::default::Default::default()
    }

    pub fn default_instance() -> &'static PubKey {
        static mut instance: ::protobuf::lazy::Lazy<PubKey> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const PubKey,
        };
        unsafe {
            instance.get(PubKey::new)
        }
    }

    // optional bytes key = 1;

    pub fn clear_key(&mut self) {
        self.key.clear();
    }

    pub fn has_key(&self) -> bool {
        self.key.is_some()
    }

    // Param is passed by value, moved
    pub fn set_key(&mut self, v: ::std::vec::Vec<u8>) {
        self.key = ::protobuf::SingularField::some(v);
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_key(&mut self) -> &mut ::std::vec::Vec<u8> {
        if self.key.is_none() {
            self.key.set_default();
        }
        self.key.as_mut().unwrap()
    }

    // Take field
    pub fn take_key(&mut self) -> ::std::vec::Vec<u8> {
        self.key.take().unwrap_or_else(|| ::std::vec::Vec::new())
    }

    pub fn get_key(&self) -> &[u8] {
        match self.key.as_ref() {
            Some(v) => &v,
            None => &[],
        }
    }

    fn get_key_for_reflect(&self) -> &::protobuf::SingularField<::std::vec::Vec<u8>> {
        &self.key
    }

    fn mut_key_for_reflect(&mut self) -> &mut ::protobuf::SingularField<::std::vec::Vec<u8>> {
        &mut self.key
    }

    // optional .tapdance.KeyType type = 2;

    pub fn clear_field_type(&mut self) {
        self.field_type = ::std::option::Option::None;
    }

    pub fn has_field_type(&self) -> bool {
        self.field_type.is_some()
    }

    // Param is passed by value, moved
    pub fn set_field_type(&mut self, v: KeyType) {
        self.field_type = ::std::option::Option::Some(v);
    }

    pub fn get_field_type(&self) -> KeyType {
        self.field_type.unwrap_or(KeyType::AES_GCM_128)
    }

    fn get_field_type_for_reflect(&self) -> &::std::option::Option<KeyType> {
        &self.field_type
    }

    fn mut_field_type_for_reflect(&mut self) -> &mut ::std::option::Option<KeyType> {
        &mut self.field_type
    }
}

impl ::protobuf::Message for PubKey {
    fn is_initialized(&self) -> bool {
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream) -> ::protobuf::ProtobufResult<()> {
        while !is.eof()? {
            let (field_number, wire_type) = is.read_tag_unpack()?;
            match field_number {
                1 => {
                    ::protobuf::rt::read_singular_bytes_into(wire_type, is, &mut self.key)?;
                },
                2 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_enum()?;
                    self.field_type = ::std::option::Option::Some(tmp);
                },
                _ => {
                    ::protobuf::rt::read_unknown_or_skip_group(field_number, wire_type, is, self.mut_unknown_fields())?;
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u32 {
        let mut my_size = 0;
        if let Some(ref v) = self.key.as_ref() {
            my_size += ::protobuf::rt::bytes_size(1, &v);
        }
        if let Some(v) = self.field_type {
            my_size += ::protobuf::rt::enum_size(2, v);
        }
        my_size += ::protobuf::rt::unknown_fields_size(self.get_unknown_fields());
        self.cached_size.set(my_size);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream) -> ::protobuf::ProtobufResult<()> {
        if let Some(ref v) = self.key.as_ref() {
            os.write_bytes(1, &v)?;
        }
        if let Some(v) = self.field_type {
            os.write_enum(2, v.value())?;
        }
        os.write_unknown_fields(self.get_unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn get_cached_size(&self) -> u32 {
        self.cached_size.get()
    }

    fn get_unknown_fields(&self) -> &::protobuf::UnknownFields {
        &self.unknown_fields
    }

    fn mut_unknown_fields(&mut self) -> &mut ::protobuf::UnknownFields {
        &mut self.unknown_fields
    }

    fn as_any(&self) -> &::std::any::Any {
        self as &::std::any::Any
    }
    fn as_any_mut(&mut self) -> &mut ::std::any::Any {
        self as &mut ::std::any::Any
    }
    fn into_any(self: Box<Self>) -> ::std::boxed::Box<::std::any::Any> {
        self
    }

    fn descriptor(&self) -> &'static ::protobuf::reflect::MessageDescriptor {
        ::protobuf::MessageStatic::descriptor_static(None::<Self>)
    }
}

impl ::protobuf::MessageStatic for PubKey {
    fn new() -> PubKey {
        PubKey::new()
    }

    fn descriptor_static(_: ::std::option::Option<PubKey>) -> &'static ::protobuf::reflect::MessageDescriptor {
        static mut descriptor: ::protobuf::lazy::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const ::protobuf::reflect::MessageDescriptor,
        };
        unsafe {
            descriptor.get(|| {
                let mut fields = ::std::vec::Vec::new();
                fields.push(::protobuf::reflect::accessor::make_singular_field_accessor::<_, ::protobuf::types::ProtobufTypeBytes>(
                    "key",
                    PubKey::get_key_for_reflect,
                    PubKey::mut_key_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeEnum<KeyType>>(
                    "type",
                    PubKey::get_field_type_for_reflect,
                    PubKey::mut_field_type_for_reflect,
                ));
                ::protobuf::reflect::MessageDescriptor::new::<PubKey>(
                    "PubKey",
                    fields,
                    file_descriptor_proto()
                )
            })
        }
    }
}

impl ::protobuf::Clear for PubKey {
    fn clear(&mut self) {
        self.clear_key();
        self.clear_field_type();
        self.unknown_fields.clear();
    }
}

impl ::std::fmt::Debug for PubKey {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for PubKey {
    fn as_ref(&self) -> ::protobuf::reflect::ProtobufValueRef {
        ::protobuf::reflect::ProtobufValueRef::Message(self)
    }
}

#[derive(PartialEq,Clone,Default)]
pub struct TLSDecoySpec {
    // message fields
    hostname: ::protobuf::SingularField<::std::string::String>,
    ipv4addr: ::std::option::Option<u32>,
    ipv6addr: ::protobuf::SingularField<::std::vec::Vec<u8>>,
    pubkey: ::protobuf::SingularPtrField<PubKey>,
    timeout: ::std::option::Option<u32>,
    tcpwin: ::std::option::Option<u32>,
    // special fields
    unknown_fields: ::protobuf::UnknownFields,
    cached_size: ::protobuf::CachedSize,
}

// see codegen.rs for the explanation why impl Sync explicitly
unsafe impl ::std::marker::Sync for TLSDecoySpec {}

impl TLSDecoySpec {
    pub fn new() -> TLSDecoySpec {
        ::std::default::Default::default()
    }

    pub fn default_instance() -> &'static TLSDecoySpec {
        static mut instance: ::protobuf::lazy::Lazy<TLSDecoySpec> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const TLSDecoySpec,
        };
        unsafe {
            instance.get(TLSDecoySpec::new)
        }
    }

    // optional string hostname = 1;

    pub fn clear_hostname(&mut self) {
        self.hostname.clear();
    }

    pub fn has_hostname(&self) -> bool {
        self.hostname.is_some()
    }

    // Param is passed by value, moved
    pub fn set_hostname(&mut self, v: ::std::string::String) {
        self.hostname = ::protobuf::SingularField::some(v);
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_hostname(&mut self) -> &mut ::std::string::String {
        if self.hostname.is_none() {
            self.hostname.set_default();
        }
        self.hostname.as_mut().unwrap()
    }

    // Take field
    pub fn take_hostname(&mut self) -> ::std::string::String {
        self.hostname.take().unwrap_or_else(|| ::std::string::String::new())
    }

    pub fn get_hostname(&self) -> &str {
        match self.hostname.as_ref() {
            Some(v) => &v,
            None => "",
        }
    }

    fn get_hostname_for_reflect(&self) -> &::protobuf::SingularField<::std::string::String> {
        &self.hostname
    }

    fn mut_hostname_for_reflect(&mut self) -> &mut ::protobuf::SingularField<::std::string::String> {
        &mut self.hostname
    }

    // optional fixed32 ipv4addr = 2;

    pub fn clear_ipv4addr(&mut self) {
        self.ipv4addr = ::std::option::Option::None;
    }

    pub fn has_ipv4addr(&self) -> bool {
        self.ipv4addr.is_some()
    }

    // Param is passed by value, moved
    pub fn set_ipv4addr(&mut self, v: u32) {
        self.ipv4addr = ::std::option::Option::Some(v);
    }

    pub fn get_ipv4addr(&self) -> u32 {
        self.ipv4addr.unwrap_or(0)
    }

    fn get_ipv4addr_for_reflect(&self) -> &::std::option::Option<u32> {
        &self.ipv4addr
    }

    fn mut_ipv4addr_for_reflect(&mut self) -> &mut ::std::option::Option<u32> {
        &mut self.ipv4addr
    }

    // optional bytes ipv6addr = 6;

    pub fn clear_ipv6addr(&mut self) {
        self.ipv6addr.clear();
    }

    pub fn has_ipv6addr(&self) -> bool {
        self.ipv6addr.is_some()
    }

    // Param is passed by value, moved
    pub fn set_ipv6addr(&mut self, v: ::std::vec::Vec<u8>) {
        self.ipv6addr = ::protobuf::SingularField::some(v);
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_ipv6addr(&mut self) -> &mut ::std::vec::Vec<u8> {
        if self.ipv6addr.is_none() {
            self.ipv6addr.set_default();
        }
        self.ipv6addr.as_mut().unwrap()
    }

    // Take field
    pub fn take_ipv6addr(&mut self) -> ::std::vec::Vec<u8> {
        self.ipv6addr.take().unwrap_or_else(|| ::std::vec::Vec::new())
    }

    pub fn get_ipv6addr(&self) -> &[u8] {
        match self.ipv6addr.as_ref() {
            Some(v) => &v,
            None => &[],
        }
    }

    fn get_ipv6addr_for_reflect(&self) -> &::protobuf::SingularField<::std::vec::Vec<u8>> {
        &self.ipv6addr
    }

    fn mut_ipv6addr_for_reflect(&mut self) -> &mut ::protobuf::SingularField<::std::vec::Vec<u8>> {
        &mut self.ipv6addr
    }

    // optional .tapdance.PubKey pubkey = 3;

    pub fn clear_pubkey(&mut self) {
        self.pubkey.clear();
    }

    pub fn has_pubkey(&self) -> bool {
        self.pubkey.is_some()
    }

    // Param is passed by value, moved
    pub fn set_pubkey(&mut self, v: PubKey) {
        self.pubkey = ::protobuf::SingularPtrField::some(v);
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_pubkey(&mut self) -> &mut PubKey {
        if self.pubkey.is_none() {
            self.pubkey.set_default();
        }
        self.pubkey.as_mut().unwrap()
    }

    // Take field
    pub fn take_pubkey(&mut self) -> PubKey {
        self.pubkey.take().unwrap_or_else(|| PubKey::new())
    }

    pub fn get_pubkey(&self) -> &PubKey {
        self.pubkey.as_ref().unwrap_or_else(|| PubKey::default_instance())
    }

    fn get_pubkey_for_reflect(&self) -> &::protobuf::SingularPtrField<PubKey> {
        &self.pubkey
    }

    fn mut_pubkey_for_reflect(&mut self) -> &mut ::protobuf::SingularPtrField<PubKey> {
        &mut self.pubkey
    }

    // optional uint32 timeout = 4;

    pub fn clear_timeout(&mut self) {
        self.timeout = ::std::option::Option::None;
    }

    pub fn has_timeout(&self) -> bool {
        self.timeout.is_some()
    }

    // Param is passed by value, moved
    pub fn set_timeout(&mut self, v: u32) {
        self.timeout = ::std::option::Option::Some(v);
    }

    pub fn get_timeout(&self) -> u32 {
        self.timeout.unwrap_or(0)
    }

    fn get_timeout_for_reflect(&self) -> &::std::option::Option<u32> {
        &self.timeout
    }

    fn mut_timeout_for_reflect(&mut self) -> &mut ::std::option::Option<u32> {
        &mut self.timeout
    }

    // optional uint32 tcpwin = 5;

    pub fn clear_tcpwin(&mut self) {
        self.tcpwin = ::std::option::Option::None;
    }

    pub fn has_tcpwin(&self) -> bool {
        self.tcpwin.is_some()
    }

    // Param is passed by value, moved
    pub fn set_tcpwin(&mut self, v: u32) {
        self.tcpwin = ::std::option::Option::Some(v);
    }

    pub fn get_tcpwin(&self) -> u32 {
        self.tcpwin.unwrap_or(0)
    }

    fn get_tcpwin_for_reflect(&self) -> &::std::option::Option<u32> {
        &self.tcpwin
    }

    fn mut_tcpwin_for_reflect(&mut self) -> &mut ::std::option::Option<u32> {
        &mut self.tcpwin
    }
}

impl ::protobuf::Message for TLSDecoySpec {
    fn is_initialized(&self) -> bool {
        for v in &self.pubkey {
            if !v.is_initialized() {
                return false;
            }
        };
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream) -> ::protobuf::ProtobufResult<()> {
        while !is.eof()? {
            let (field_number, wire_type) = is.read_tag_unpack()?;
            match field_number {
                1 => {
                    ::protobuf::rt::read_singular_string_into(wire_type, is, &mut self.hostname)?;
                },
                2 => {
                    if wire_type != ::protobuf::wire_format::WireTypeFixed32 {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_fixed32()?;
                    self.ipv4addr = ::std::option::Option::Some(tmp);
                },
                6 => {
                    ::protobuf::rt::read_singular_bytes_into(wire_type, is, &mut self.ipv6addr)?;
                },
                3 => {
                    ::protobuf::rt::read_singular_message_into(wire_type, is, &mut self.pubkey)?;
                },
                4 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_uint32()?;
                    self.timeout = ::std::option::Option::Some(tmp);
                },
                5 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_uint32()?;
                    self.tcpwin = ::std::option::Option::Some(tmp);
                },
                _ => {
                    ::protobuf::rt::read_unknown_or_skip_group(field_number, wire_type, is, self.mut_unknown_fields())?;
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u32 {
        let mut my_size = 0;
        if let Some(ref v) = self.hostname.as_ref() {
            my_size += ::protobuf::rt::string_size(1, &v);
        }
        if let Some(v) = self.ipv4addr {
            my_size += 5;
        }
        if let Some(ref v) = self.ipv6addr.as_ref() {
            my_size += ::protobuf::rt::bytes_size(6, &v);
        }
        if let Some(ref v) = self.pubkey.as_ref() {
            let len = v.compute_size();
            my_size += 1 + ::protobuf::rt::compute_raw_varint32_size(len) + len;
        }
        if let Some(v) = self.timeout {
            my_size += ::protobuf::rt::value_size(4, v, ::protobuf::wire_format::WireTypeVarint);
        }
        if let Some(v) = self.tcpwin {
            my_size += ::protobuf::rt::value_size(5, v, ::protobuf::wire_format::WireTypeVarint);
        }
        my_size += ::protobuf::rt::unknown_fields_size(self.get_unknown_fields());
        self.cached_size.set(my_size);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream) -> ::protobuf::ProtobufResult<()> {
        if let Some(ref v) = self.hostname.as_ref() {
            os.write_string(1, &v)?;
        }
        if let Some(v) = self.ipv4addr {
            os.write_fixed32(2, v)?;
        }
        if let Some(ref v) = self.ipv6addr.as_ref() {
            os.write_bytes(6, &v)?;
        }
        if let Some(ref v) = self.pubkey.as_ref() {
            os.write_tag(3, ::protobuf::wire_format::WireTypeLengthDelimited)?;
            os.write_raw_varint32(v.get_cached_size())?;
            v.write_to_with_cached_sizes(os)?;
        }
        if let Some(v) = self.timeout {
            os.write_uint32(4, v)?;
        }
        if let Some(v) = self.tcpwin {
            os.write_uint32(5, v)?;
        }
        os.write_unknown_fields(self.get_unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn get_cached_size(&self) -> u32 {
        self.cached_size.get()
    }

    fn get_unknown_fields(&self) -> &::protobuf::UnknownFields {
        &self.unknown_fields
    }

    fn mut_unknown_fields(&mut self) -> &mut ::protobuf::UnknownFields {
        &mut self.unknown_fields
    }

    fn as_any(&self) -> &::std::any::Any {
        self as &::std::any::Any
    }
    fn as_any_mut(&mut self) -> &mut ::std::any::Any {
        self as &mut ::std::any::Any
    }
    fn into_any(self: Box<Self>) -> ::std::boxed::Box<::std::any::Any> {
        self
    }

    fn descriptor(&self) -> &'static ::protobuf::reflect::MessageDescriptor {
        ::protobuf::MessageStatic::descriptor_static(None::<Self>)
    }
}

impl ::protobuf::MessageStatic for TLSDecoySpec {
    fn new() -> TLSDecoySpec {
        TLSDecoySpec::new()
    }

    fn descriptor_static(_: ::std::option::Option<TLSDecoySpec>) -> &'static ::protobuf::reflect::MessageDescriptor {
        static mut descriptor: ::protobuf::lazy::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const ::protobuf::reflect::MessageDescriptor,
        };
        unsafe {
            descriptor.get(|| {
                let mut fields = ::std::vec::Vec::new();
                fields.push(::protobuf::reflect::accessor::make_singular_field_accessor::<_, ::protobuf::types::ProtobufTypeString>(
                    "hostname",
                    TLSDecoySpec::get_hostname_for_reflect,
                    TLSDecoySpec::mut_hostname_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeFixed32>(
                    "ipv4addr",
                    TLSDecoySpec::get_ipv4addr_for_reflect,
                    TLSDecoySpec::mut_ipv4addr_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_singular_field_accessor::<_, ::protobuf::types::ProtobufTypeBytes>(
                    "ipv6addr",
                    TLSDecoySpec::get_ipv6addr_for_reflect,
                    TLSDecoySpec::mut_ipv6addr_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_singular_ptr_field_accessor::<_, ::protobuf::types::ProtobufTypeMessage<PubKey>>(
                    "pubkey",
                    TLSDecoySpec::get_pubkey_for_reflect,
                    TLSDecoySpec::mut_pubkey_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeUint32>(
                    "timeout",
                    TLSDecoySpec::get_timeout_for_reflect,
                    TLSDecoySpec::mut_timeout_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeUint32>(
                    "tcpwin",
                    TLSDecoySpec::get_tcpwin_for_reflect,
                    TLSDecoySpec::mut_tcpwin_for_reflect,
                ));
                ::protobuf::reflect::MessageDescriptor::new::<TLSDecoySpec>(
                    "TLSDecoySpec",
                    fields,
                    file_descriptor_proto()
                )
            })
        }
    }
}

impl ::protobuf::Clear for TLSDecoySpec {
    fn clear(&mut self) {
        self.clear_hostname();
        self.clear_ipv4addr();
        self.clear_ipv6addr();
        self.clear_pubkey();
        self.clear_timeout();
        self.clear_tcpwin();
        self.unknown_fields.clear();
    }
}

impl ::std::fmt::Debug for TLSDecoySpec {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for TLSDecoySpec {
    fn as_ref(&self) -> ::protobuf::reflect::ProtobufValueRef {
        ::protobuf::reflect::ProtobufValueRef::Message(self)
    }
}

#[derive(PartialEq,Clone,Default)]
pub struct ClientConf {
    // message fields
    decoy_list: ::protobuf::SingularPtrField<DecoyList>,
    generation: ::std::option::Option<u32>,
    default_pubkey: ::protobuf::SingularPtrField<PubKey>,
    // special fields
    unknown_fields: ::protobuf::UnknownFields,
    cached_size: ::protobuf::CachedSize,
}

// see codegen.rs for the explanation why impl Sync explicitly
unsafe impl ::std::marker::Sync for ClientConf {}

impl ClientConf {
    pub fn new() -> ClientConf {
        ::std::default::Default::default()
    }

    pub fn default_instance() -> &'static ClientConf {
        static mut instance: ::protobuf::lazy::Lazy<ClientConf> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const ClientConf,
        };
        unsafe {
            instance.get(ClientConf::new)
        }
    }

    // optional .tapdance.DecoyList decoy_list = 1;

    pub fn clear_decoy_list(&mut self) {
        self.decoy_list.clear();
    }

    pub fn has_decoy_list(&self) -> bool {
        self.decoy_list.is_some()
    }

    // Param is passed by value, moved
    pub fn set_decoy_list(&mut self, v: DecoyList) {
        self.decoy_list = ::protobuf::SingularPtrField::some(v);
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_decoy_list(&mut self) -> &mut DecoyList {
        if self.decoy_list.is_none() {
            self.decoy_list.set_default();
        }
        self.decoy_list.as_mut().unwrap()
    }

    // Take field
    pub fn take_decoy_list(&mut self) -> DecoyList {
        self.decoy_list.take().unwrap_or_else(|| DecoyList::new())
    }

    pub fn get_decoy_list(&self) -> &DecoyList {
        self.decoy_list.as_ref().unwrap_or_else(|| DecoyList::default_instance())
    }

    fn get_decoy_list_for_reflect(&self) -> &::protobuf::SingularPtrField<DecoyList> {
        &self.decoy_list
    }

    fn mut_decoy_list_for_reflect(&mut self) -> &mut ::protobuf::SingularPtrField<DecoyList> {
        &mut self.decoy_list
    }

    // optional uint32 generation = 2;

    pub fn clear_generation(&mut self) {
        self.generation = ::std::option::Option::None;
    }

    pub fn has_generation(&self) -> bool {
        self.generation.is_some()
    }

    // Param is passed by value, moved
    pub fn set_generation(&mut self, v: u32) {
        self.generation = ::std::option::Option::Some(v);
    }

    pub fn get_generation(&self) -> u32 {
        self.generation.unwrap_or(0)
    }

    fn get_generation_for_reflect(&self) -> &::std::option::Option<u32> {
        &self.generation
    }

    fn mut_generation_for_reflect(&mut self) -> &mut ::std::option::Option<u32> {
        &mut self.generation
    }

    // optional .tapdance.PubKey default_pubkey = 3;

    pub fn clear_default_pubkey(&mut self) {
        self.default_pubkey.clear();
    }

    pub fn has_default_pubkey(&self) -> bool {
        self.default_pubkey.is_some()
    }

    // Param is passed by value, moved
    pub fn set_default_pubkey(&mut self, v: PubKey) {
        self.default_pubkey = ::protobuf::SingularPtrField::some(v);
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_default_pubkey(&mut self) -> &mut PubKey {
        if self.default_pubkey.is_none() {
            self.default_pubkey.set_default();
        }
        self.default_pubkey.as_mut().unwrap()
    }

    // Take field
    pub fn take_default_pubkey(&mut self) -> PubKey {
        self.default_pubkey.take().unwrap_or_else(|| PubKey::new())
    }

    pub fn get_default_pubkey(&self) -> &PubKey {
        self.default_pubkey.as_ref().unwrap_or_else(|| PubKey::default_instance())
    }

    fn get_default_pubkey_for_reflect(&self) -> &::protobuf::SingularPtrField<PubKey> {
        &self.default_pubkey
    }

    fn mut_default_pubkey_for_reflect(&mut self) -> &mut ::protobuf::SingularPtrField<PubKey> {
        &mut self.default_pubkey
    }
}

impl ::protobuf::Message for ClientConf {
    fn is_initialized(&self) -> bool {
        for v in &self.decoy_list {
            if !v.is_initialized() {
                return false;
            }
        };
        for v in &self.default_pubkey {
            if !v.is_initialized() {
                return false;
            }
        };
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream) -> ::protobuf::ProtobufResult<()> {
        while !is.eof()? {
            let (field_number, wire_type) = is.read_tag_unpack()?;
            match field_number {
                1 => {
                    ::protobuf::rt::read_singular_message_into(wire_type, is, &mut self.decoy_list)?;
                },
                2 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_uint32()?;
                    self.generation = ::std::option::Option::Some(tmp);
                },
                3 => {
                    ::protobuf::rt::read_singular_message_into(wire_type, is, &mut self.default_pubkey)?;
                },
                _ => {
                    ::protobuf::rt::read_unknown_or_skip_group(field_number, wire_type, is, self.mut_unknown_fields())?;
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u32 {
        let mut my_size = 0;
        if let Some(ref v) = self.decoy_list.as_ref() {
            let len = v.compute_size();
            my_size += 1 + ::protobuf::rt::compute_raw_varint32_size(len) + len;
        }
        if let Some(v) = self.generation {
            my_size += ::protobuf::rt::value_size(2, v, ::protobuf::wire_format::WireTypeVarint);
        }
        if let Some(ref v) = self.default_pubkey.as_ref() {
            let len = v.compute_size();
            my_size += 1 + ::protobuf::rt::compute_raw_varint32_size(len) + len;
        }
        my_size += ::protobuf::rt::unknown_fields_size(self.get_unknown_fields());
        self.cached_size.set(my_size);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream) -> ::protobuf::ProtobufResult<()> {
        if let Some(ref v) = self.decoy_list.as_ref() {
            os.write_tag(1, ::protobuf::wire_format::WireTypeLengthDelimited)?;
            os.write_raw_varint32(v.get_cached_size())?;
            v.write_to_with_cached_sizes(os)?;
        }
        if let Some(v) = self.generation {
            os.write_uint32(2, v)?;
        }
        if let Some(ref v) = self.default_pubkey.as_ref() {
            os.write_tag(3, ::protobuf::wire_format::WireTypeLengthDelimited)?;
            os.write_raw_varint32(v.get_cached_size())?;
            v.write_to_with_cached_sizes(os)?;
        }
        os.write_unknown_fields(self.get_unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn get_cached_size(&self) -> u32 {
        self.cached_size.get()
    }

    fn get_unknown_fields(&self) -> &::protobuf::UnknownFields {
        &self.unknown_fields
    }

    fn mut_unknown_fields(&mut self) -> &mut ::protobuf::UnknownFields {
        &mut self.unknown_fields
    }

    fn as_any(&self) -> &::std::any::Any {
        self as &::std::any::Any
    }
    fn as_any_mut(&mut self) -> &mut ::std::any::Any {
        self as &mut ::std::any::Any
    }
    fn into_any(self: Box<Self>) -> ::std::boxed::Box<::std::any::Any> {
        self
    }

    fn descriptor(&self) -> &'static ::protobuf::reflect::MessageDescriptor {
        ::protobuf::MessageStatic::descriptor_static(None::<Self>)
    }
}

impl ::protobuf::MessageStatic for ClientConf {
    fn new() -> ClientConf {
        ClientConf::new()
    }

    fn descriptor_static(_: ::std::option::Option<ClientConf>) -> &'static ::protobuf::reflect::MessageDescriptor {
        static mut descriptor: ::protobuf::lazy::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const ::protobuf::reflect::MessageDescriptor,
        };
        unsafe {
            descriptor.get(|| {
                let mut fields = ::std::vec::Vec::new();
                fields.push(::protobuf::reflect::accessor::make_singular_ptr_field_accessor::<_, ::protobuf::types::ProtobufTypeMessage<DecoyList>>(
                    "decoy_list",
                    ClientConf::get_decoy_list_for_reflect,
                    ClientConf::mut_decoy_list_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeUint32>(
                    "generation",
                    ClientConf::get_generation_for_reflect,
                    ClientConf::mut_generation_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_singular_ptr_field_accessor::<_, ::protobuf::types::ProtobufTypeMessage<PubKey>>(
                    "default_pubkey",
                    ClientConf::get_default_pubkey_for_reflect,
                    ClientConf::mut_default_pubkey_for_reflect,
                ));
                ::protobuf::reflect::MessageDescriptor::new::<ClientConf>(
                    "ClientConf",
                    fields,
                    file_descriptor_proto()
                )
            })
        }
    }
}

impl ::protobuf::Clear for ClientConf {
    fn clear(&mut self) {
        self.clear_decoy_list();
        self.clear_generation();
        self.clear_default_pubkey();
        self.unknown_fields.clear();
    }
}

impl ::std::fmt::Debug for ClientConf {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for ClientConf {
    fn as_ref(&self) -> ::protobuf::reflect::ProtobufValueRef {
        ::protobuf::reflect::ProtobufValueRef::Message(self)
    }
}

#[derive(PartialEq,Clone,Default)]
pub struct DecoyList {
    // message fields
    tls_decoys: ::protobuf::RepeatedField<TLSDecoySpec>,
    // special fields
    unknown_fields: ::protobuf::UnknownFields,
    cached_size: ::protobuf::CachedSize,
}

// see codegen.rs for the explanation why impl Sync explicitly
unsafe impl ::std::marker::Sync for DecoyList {}

impl DecoyList {
    pub fn new() -> DecoyList {
        ::std::default::Default::default()
    }

    pub fn default_instance() -> &'static DecoyList {
        static mut instance: ::protobuf::lazy::Lazy<DecoyList> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const DecoyList,
        };
        unsafe {
            instance.get(DecoyList::new)
        }
    }

    // repeated .tapdance.TLSDecoySpec tls_decoys = 1;

    pub fn clear_tls_decoys(&mut self) {
        self.tls_decoys.clear();
    }

    // Param is passed by value, moved
    pub fn set_tls_decoys(&mut self, v: ::protobuf::RepeatedField<TLSDecoySpec>) {
        self.tls_decoys = v;
    }

    // Mutable pointer to the field.
    pub fn mut_tls_decoys(&mut self) -> &mut ::protobuf::RepeatedField<TLSDecoySpec> {
        &mut self.tls_decoys
    }

    // Take field
    pub fn take_tls_decoys(&mut self) -> ::protobuf::RepeatedField<TLSDecoySpec> {
        ::std::mem::replace(&mut self.tls_decoys, ::protobuf::RepeatedField::new())
    }

    pub fn get_tls_decoys(&self) -> &[TLSDecoySpec] {
        &self.tls_decoys
    }

    fn get_tls_decoys_for_reflect(&self) -> &::protobuf::RepeatedField<TLSDecoySpec> {
        &self.tls_decoys
    }

    fn mut_tls_decoys_for_reflect(&mut self) -> &mut ::protobuf::RepeatedField<TLSDecoySpec> {
        &mut self.tls_decoys
    }
}

impl ::protobuf::Message for DecoyList {
    fn is_initialized(&self) -> bool {
        for v in &self.tls_decoys {
            if !v.is_initialized() {
                return false;
            }
        };
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream) -> ::protobuf::ProtobufResult<()> {
        while !is.eof()? {
            let (field_number, wire_type) = is.read_tag_unpack()?;
            match field_number {
                1 => {
                    ::protobuf::rt::read_repeated_message_into(wire_type, is, &mut self.tls_decoys)?;
                },
                _ => {
                    ::protobuf::rt::read_unknown_or_skip_group(field_number, wire_type, is, self.mut_unknown_fields())?;
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u32 {
        let mut my_size = 0;
        for value in &self.tls_decoys {
            let len = value.compute_size();
            my_size += 1 + ::protobuf::rt::compute_raw_varint32_size(len) + len;
        };
        my_size += ::protobuf::rt::unknown_fields_size(self.get_unknown_fields());
        self.cached_size.set(my_size);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream) -> ::protobuf::ProtobufResult<()> {
        for v in &self.tls_decoys {
            os.write_tag(1, ::protobuf::wire_format::WireTypeLengthDelimited)?;
            os.write_raw_varint32(v.get_cached_size())?;
            v.write_to_with_cached_sizes(os)?;
        };
        os.write_unknown_fields(self.get_unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn get_cached_size(&self) -> u32 {
        self.cached_size.get()
    }

    fn get_unknown_fields(&self) -> &::protobuf::UnknownFields {
        &self.unknown_fields
    }

    fn mut_unknown_fields(&mut self) -> &mut ::protobuf::UnknownFields {
        &mut self.unknown_fields
    }

    fn as_any(&self) -> &::std::any::Any {
        self as &::std::any::Any
    }
    fn as_any_mut(&mut self) -> &mut ::std::any::Any {
        self as &mut ::std::any::Any
    }
    fn into_any(self: Box<Self>) -> ::std::boxed::Box<::std::any::Any> {
        self
    }

    fn descriptor(&self) -> &'static ::protobuf::reflect::MessageDescriptor {
        ::protobuf::MessageStatic::descriptor_static(None::<Self>)
    }
}

impl ::protobuf::MessageStatic for DecoyList {
    fn new() -> DecoyList {
        DecoyList::new()
    }

    fn descriptor_static(_: ::std::option::Option<DecoyList>) -> &'static ::protobuf::reflect::MessageDescriptor {
        static mut descriptor: ::protobuf::lazy::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const ::protobuf::reflect::MessageDescriptor,
        };
        unsafe {
            descriptor.get(|| {
                let mut fields = ::std::vec::Vec::new();
                fields.push(::protobuf::reflect::accessor::make_repeated_field_accessor::<_, ::protobuf::types::ProtobufTypeMessage<TLSDecoySpec>>(
                    "tls_decoys",
                    DecoyList::get_tls_decoys_for_reflect,
                    DecoyList::mut_tls_decoys_for_reflect,
                ));
                ::protobuf::reflect::MessageDescriptor::new::<DecoyList>(
                    "DecoyList",
                    fields,
                    file_descriptor_proto()
                )
            })
        }
    }
}

impl ::protobuf::Clear for DecoyList {
    fn clear(&mut self) {
        self.clear_tls_decoys();
        self.unknown_fields.clear();
    }
}

impl ::std::fmt::Debug for DecoyList {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for DecoyList {
    fn as_ref(&self) -> ::protobuf::reflect::ProtobufValueRef {
        ::protobuf::reflect::ProtobufValueRef::Message(self)
    }
}

#[derive(PartialEq,Clone,Default)]
pub struct StationToClient {
    // message fields
    protocol_version: ::std::option::Option<u32>,
    state_transition: ::std::option::Option<S2C_Transition>,
    config_info: ::protobuf::SingularPtrField<ClientConf>,
    err_reason: ::std::option::Option<ErrorReasonS2C>,
    tmp_backoff: ::std::option::Option<u32>,
    station_id: ::protobuf::SingularField<::std::string::String>,
    padding: ::protobuf::SingularField<::std::vec::Vec<u8>>,
    // special fields
    unknown_fields: ::protobuf::UnknownFields,
    cached_size: ::protobuf::CachedSize,
}

// see codegen.rs for the explanation why impl Sync explicitly
unsafe impl ::std::marker::Sync for StationToClient {}

impl StationToClient {
    pub fn new() -> StationToClient {
        ::std::default::Default::default()
    }

    pub fn default_instance() -> &'static StationToClient {
        static mut instance: ::protobuf::lazy::Lazy<StationToClient> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const StationToClient,
        };
        unsafe {
            instance.get(StationToClient::new)
        }
    }

    // optional uint32 protocol_version = 1;

    pub fn clear_protocol_version(&mut self) {
        self.protocol_version = ::std::option::Option::None;
    }

    pub fn has_protocol_version(&self) -> bool {
        self.protocol_version.is_some()
    }

    // Param is passed by value, moved
    pub fn set_protocol_version(&mut self, v: u32) {
        self.protocol_version = ::std::option::Option::Some(v);
    }

    pub fn get_protocol_version(&self) -> u32 {
        self.protocol_version.unwrap_or(0)
    }

    fn get_protocol_version_for_reflect(&self) -> &::std::option::Option<u32> {
        &self.protocol_version
    }

    fn mut_protocol_version_for_reflect(&mut self) -> &mut ::std::option::Option<u32> {
        &mut self.protocol_version
    }

    // optional .tapdance.S2C_Transition state_transition = 2;

    pub fn clear_state_transition(&mut self) {
        self.state_transition = ::std::option::Option::None;
    }

    pub fn has_state_transition(&self) -> bool {
        self.state_transition.is_some()
    }

    // Param is passed by value, moved
    pub fn set_state_transition(&mut self, v: S2C_Transition) {
        self.state_transition = ::std::option::Option::Some(v);
    }

    pub fn get_state_transition(&self) -> S2C_Transition {
        self.state_transition.unwrap_or(S2C_Transition::S2C_NO_CHANGE)
    }

    fn get_state_transition_for_reflect(&self) -> &::std::option::Option<S2C_Transition> {
        &self.state_transition
    }

    fn mut_state_transition_for_reflect(&mut self) -> &mut ::std::option::Option<S2C_Transition> {
        &mut self.state_transition
    }

    // optional .tapdance.ClientConf config_info = 3;

    pub fn clear_config_info(&mut self) {
        self.config_info.clear();
    }

    pub fn has_config_info(&self) -> bool {
        self.config_info.is_some()
    }

    // Param is passed by value, moved
    pub fn set_config_info(&mut self, v: ClientConf) {
        self.config_info = ::protobuf::SingularPtrField::some(v);
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_config_info(&mut self) -> &mut ClientConf {
        if self.config_info.is_none() {
            self.config_info.set_default();
        }
        self.config_info.as_mut().unwrap()
    }

    // Take field
    pub fn take_config_info(&mut self) -> ClientConf {
        self.config_info.take().unwrap_or_else(|| ClientConf::new())
    }

    pub fn get_config_info(&self) -> &ClientConf {
        self.config_info.as_ref().unwrap_or_else(|| ClientConf::default_instance())
    }

    fn get_config_info_for_reflect(&self) -> &::protobuf::SingularPtrField<ClientConf> {
        &self.config_info
    }

    fn mut_config_info_for_reflect(&mut self) -> &mut ::protobuf::SingularPtrField<ClientConf> {
        &mut self.config_info
    }

    // optional .tapdance.ErrorReasonS2C err_reason = 4;

    pub fn clear_err_reason(&mut self) {
        self.err_reason = ::std::option::Option::None;
    }

    pub fn has_err_reason(&self) -> bool {
        self.err_reason.is_some()
    }

    // Param is passed by value, moved
    pub fn set_err_reason(&mut self, v: ErrorReasonS2C) {
        self.err_reason = ::std::option::Option::Some(v);
    }

    pub fn get_err_reason(&self) -> ErrorReasonS2C {
        self.err_reason.unwrap_or(ErrorReasonS2C::NO_ERROR)
    }

    fn get_err_reason_for_reflect(&self) -> &::std::option::Option<ErrorReasonS2C> {
        &self.err_reason
    }

    fn mut_err_reason_for_reflect(&mut self) -> &mut ::std::option::Option<ErrorReasonS2C> {
        &mut self.err_reason
    }

    // optional uint32 tmp_backoff = 5;

    pub fn clear_tmp_backoff(&mut self) {
        self.tmp_backoff = ::std::option::Option::None;
    }

    pub fn has_tmp_backoff(&self) -> bool {
        self.tmp_backoff.is_some()
    }

    // Param is passed by value, moved
    pub fn set_tmp_backoff(&mut self, v: u32) {
        self.tmp_backoff = ::std::option::Option::Some(v);
    }

    pub fn get_tmp_backoff(&self) -> u32 {
        self.tmp_backoff.unwrap_or(0)
    }

    fn get_tmp_backoff_for_reflect(&self) -> &::std::option::Option<u32> {
        &self.tmp_backoff
    }

    fn mut_tmp_backoff_for_reflect(&mut self) -> &mut ::std::option::Option<u32> {
        &mut self.tmp_backoff
    }

    // optional string station_id = 6;

    pub fn clear_station_id(&mut self) {
        self.station_id.clear();
    }

    pub fn has_station_id(&self) -> bool {
        self.station_id.is_some()
    }

    // Param is passed by value, moved
    pub fn set_station_id(&mut self, v: ::std::string::String) {
        self.station_id = ::protobuf::SingularField::some(v);
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_station_id(&mut self) -> &mut ::std::string::String {
        if self.station_id.is_none() {
            self.station_id.set_default();
        }
        self.station_id.as_mut().unwrap()
    }

    // Take field
    pub fn take_station_id(&mut self) -> ::std::string::String {
        self.station_id.take().unwrap_or_else(|| ::std::string::String::new())
    }

    pub fn get_station_id(&self) -> &str {
        match self.station_id.as_ref() {
            Some(v) => &v,
            None => "",
        }
    }

    fn get_station_id_for_reflect(&self) -> &::protobuf::SingularField<::std::string::String> {
        &self.station_id
    }

    fn mut_station_id_for_reflect(&mut self) -> &mut ::protobuf::SingularField<::std::string::String> {
        &mut self.station_id
    }

    // optional bytes padding = 100;

    pub fn clear_padding(&mut self) {
        self.padding.clear();
    }

    pub fn has_padding(&self) -> bool {
        self.padding.is_some()
    }

    // Param is passed by value, moved
    pub fn set_padding(&mut self, v: ::std::vec::Vec<u8>) {
        self.padding = ::protobuf::SingularField::some(v);
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_padding(&mut self) -> &mut ::std::vec::Vec<u8> {
        if self.padding.is_none() {
            self.padding.set_default();
        }
        self.padding.as_mut().unwrap()
    }

    // Take field
    pub fn take_padding(&mut self) -> ::std::vec::Vec<u8> {
        self.padding.take().unwrap_or_else(|| ::std::vec::Vec::new())
    }

    pub fn get_padding(&self) -> &[u8] {
        match self.padding.as_ref() {
            Some(v) => &v,
            None => &[],
        }
    }

    fn get_padding_for_reflect(&self) -> &::protobuf::SingularField<::std::vec::Vec<u8>> {
        &self.padding
    }

    fn mut_padding_for_reflect(&mut self) -> &mut ::protobuf::SingularField<::std::vec::Vec<u8>> {
        &mut self.padding
    }
}

impl ::protobuf::Message for StationToClient {
    fn is_initialized(&self) -> bool {
        for v in &self.config_info {
            if !v.is_initialized() {
                return false;
            }
        };
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream) -> ::protobuf::ProtobufResult<()> {
        while !is.eof()? {
            let (field_number, wire_type) = is.read_tag_unpack()?;
            match field_number {
                1 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_uint32()?;
                    self.protocol_version = ::std::option::Option::Some(tmp);
                },
                2 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_enum()?;
                    self.state_transition = ::std::option::Option::Some(tmp);
                },
                3 => {
                    ::protobuf::rt::read_singular_message_into(wire_type, is, &mut self.config_info)?;
                },
                4 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_enum()?;
                    self.err_reason = ::std::option::Option::Some(tmp);
                },
                5 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_uint32()?;
                    self.tmp_backoff = ::std::option::Option::Some(tmp);
                },
                6 => {
                    ::protobuf::rt::read_singular_string_into(wire_type, is, &mut self.station_id)?;
                },
                100 => {
                    ::protobuf::rt::read_singular_bytes_into(wire_type, is, &mut self.padding)?;
                },
                _ => {
                    ::protobuf::rt::read_unknown_or_skip_group(field_number, wire_type, is, self.mut_unknown_fields())?;
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u32 {
        let mut my_size = 0;
        if let Some(v) = self.protocol_version {
            my_size += ::protobuf::rt::value_size(1, v, ::protobuf::wire_format::WireTypeVarint);
        }
        if let Some(v) = self.state_transition {
            my_size += ::protobuf::rt::enum_size(2, v);
        }
        if let Some(ref v) = self.config_info.as_ref() {
            let len = v.compute_size();
            my_size += 1 + ::protobuf::rt::compute_raw_varint32_size(len) + len;
        }
        if let Some(v) = self.err_reason {
            my_size += ::protobuf::rt::enum_size(4, v);
        }
        if let Some(v) = self.tmp_backoff {
            my_size += ::protobuf::rt::value_size(5, v, ::protobuf::wire_format::WireTypeVarint);
        }
        if let Some(ref v) = self.station_id.as_ref() {
            my_size += ::protobuf::rt::string_size(6, &v);
        }
        if let Some(ref v) = self.padding.as_ref() {
            my_size += ::protobuf::rt::bytes_size(100, &v);
        }
        my_size += ::protobuf::rt::unknown_fields_size(self.get_unknown_fields());
        self.cached_size.set(my_size);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream) -> ::protobuf::ProtobufResult<()> {
        if let Some(v) = self.protocol_version {
            os.write_uint32(1, v)?;
        }
        if let Some(v) = self.state_transition {
            os.write_enum(2, v.value())?;
        }
        if let Some(ref v) = self.config_info.as_ref() {
            os.write_tag(3, ::protobuf::wire_format::WireTypeLengthDelimited)?;
            os.write_raw_varint32(v.get_cached_size())?;
            v.write_to_with_cached_sizes(os)?;
        }
        if let Some(v) = self.err_reason {
            os.write_enum(4, v.value())?;
        }
        if let Some(v) = self.tmp_backoff {
            os.write_uint32(5, v)?;
        }
        if let Some(ref v) = self.station_id.as_ref() {
            os.write_string(6, &v)?;
        }
        if let Some(ref v) = self.padding.as_ref() {
            os.write_bytes(100, &v)?;
        }
        os.write_unknown_fields(self.get_unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn get_cached_size(&self) -> u32 {
        self.cached_size.get()
    }

    fn get_unknown_fields(&self) -> &::protobuf::UnknownFields {
        &self.unknown_fields
    }

    fn mut_unknown_fields(&mut self) -> &mut ::protobuf::UnknownFields {
        &mut self.unknown_fields
    }

    fn as_any(&self) -> &::std::any::Any {
        self as &::std::any::Any
    }
    fn as_any_mut(&mut self) -> &mut ::std::any::Any {
        self as &mut ::std::any::Any
    }
    fn into_any(self: Box<Self>) -> ::std::boxed::Box<::std::any::Any> {
        self
    }

    fn descriptor(&self) -> &'static ::protobuf::reflect::MessageDescriptor {
        ::protobuf::MessageStatic::descriptor_static(None::<Self>)
    }
}

impl ::protobuf::MessageStatic for StationToClient {
    fn new() -> StationToClient {
        StationToClient::new()
    }

    fn descriptor_static(_: ::std::option::Option<StationToClient>) -> &'static ::protobuf::reflect::MessageDescriptor {
        static mut descriptor: ::protobuf::lazy::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const ::protobuf::reflect::MessageDescriptor,
        };
        unsafe {
            descriptor.get(|| {
                let mut fields = ::std::vec::Vec::new();
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeUint32>(
                    "protocol_version",
                    StationToClient::get_protocol_version_for_reflect,
                    StationToClient::mut_protocol_version_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeEnum<S2C_Transition>>(
                    "state_transition",
                    StationToClient::get_state_transition_for_reflect,
                    StationToClient::mut_state_transition_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_singular_ptr_field_accessor::<_, ::protobuf::types::ProtobufTypeMessage<ClientConf>>(
                    "config_info",
                    StationToClient::get_config_info_for_reflect,
                    StationToClient::mut_config_info_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeEnum<ErrorReasonS2C>>(
                    "err_reason",
                    StationToClient::get_err_reason_for_reflect,
                    StationToClient::mut_err_reason_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeUint32>(
                    "tmp_backoff",
                    StationToClient::get_tmp_backoff_for_reflect,
                    StationToClient::mut_tmp_backoff_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_singular_field_accessor::<_, ::protobuf::types::ProtobufTypeString>(
                    "station_id",
                    StationToClient::get_station_id_for_reflect,
                    StationToClient::mut_station_id_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_singular_field_accessor::<_, ::protobuf::types::ProtobufTypeBytes>(
                    "padding",
                    StationToClient::get_padding_for_reflect,
                    StationToClient::mut_padding_for_reflect,
                ));
                ::protobuf::reflect::MessageDescriptor::new::<StationToClient>(
                    "StationToClient",
                    fields,
                    file_descriptor_proto()
                )
            })
        }
    }
}

impl ::protobuf::Clear for StationToClient {
    fn clear(&mut self) {
        self.clear_protocol_version();
        self.clear_state_transition();
        self.clear_config_info();
        self.clear_err_reason();
        self.clear_tmp_backoff();
        self.clear_station_id();
        self.clear_padding();
        self.unknown_fields.clear();
    }
}

impl ::std::fmt::Debug for StationToClient {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for StationToClient {
    fn as_ref(&self) -> ::protobuf::reflect::ProtobufValueRef {
        ::protobuf::reflect::ProtobufValueRef::Message(self)
    }
}

#[derive(PartialEq,Clone,Default)]
pub struct ClientToStation {
    // message fields
    protocol_version: ::std::option::Option<u32>,
    decoy_list_generation: ::std::option::Option<u32>,
    state_transition: ::std::option::Option<C2S_Transition>,
    upload_sync: ::std::option::Option<u64>,
    failed_decoys: ::protobuf::RepeatedField<::std::string::String>,
    stats: ::protobuf::SingularPtrField<SessionStats>,
    covert_address: ::protobuf::SingularField<::std::string::String>,
    masked_decoy_server_name: ::protobuf::SingularField<::std::string::String>,
    padding: ::protobuf::SingularField<::std::vec::Vec<u8>>,
    // special fields
    unknown_fields: ::protobuf::UnknownFields,
    cached_size: ::protobuf::CachedSize,
}

// see codegen.rs for the explanation why impl Sync explicitly
unsafe impl ::std::marker::Sync for ClientToStation {}

impl ClientToStation {
    pub fn new() -> ClientToStation {
        ::std::default::Default::default()
    }

    pub fn default_instance() -> &'static ClientToStation {
        static mut instance: ::protobuf::lazy::Lazy<ClientToStation> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const ClientToStation,
        };
        unsafe {
            instance.get(ClientToStation::new)
        }
    }

    // optional uint32 protocol_version = 1;

    pub fn clear_protocol_version(&mut self) {
        self.protocol_version = ::std::option::Option::None;
    }

    pub fn has_protocol_version(&self) -> bool {
        self.protocol_version.is_some()
    }

    // Param is passed by value, moved
    pub fn set_protocol_version(&mut self, v: u32) {
        self.protocol_version = ::std::option::Option::Some(v);
    }

    pub fn get_protocol_version(&self) -> u32 {
        self.protocol_version.unwrap_or(0)
    }

    fn get_protocol_version_for_reflect(&self) -> &::std::option::Option<u32> {
        &self.protocol_version
    }

    fn mut_protocol_version_for_reflect(&mut self) -> &mut ::std::option::Option<u32> {
        &mut self.protocol_version
    }

    // optional uint32 decoy_list_generation = 2;

    pub fn clear_decoy_list_generation(&mut self) {
        self.decoy_list_generation = ::std::option::Option::None;
    }

    pub fn has_decoy_list_generation(&self) -> bool {
        self.decoy_list_generation.is_some()
    }

    // Param is passed by value, moved
    pub fn set_decoy_list_generation(&mut self, v: u32) {
        self.decoy_list_generation = ::std::option::Option::Some(v);
    }

    pub fn get_decoy_list_generation(&self) -> u32 {
        self.decoy_list_generation.unwrap_or(0)
    }

    fn get_decoy_list_generation_for_reflect(&self) -> &::std::option::Option<u32> {
        &self.decoy_list_generation
    }

    fn mut_decoy_list_generation_for_reflect(&mut self) -> &mut ::std::option::Option<u32> {
        &mut self.decoy_list_generation
    }

    // optional .tapdance.C2S_Transition state_transition = 3;

    pub fn clear_state_transition(&mut self) {
        self.state_transition = ::std::option::Option::None;
    }

    pub fn has_state_transition(&self) -> bool {
        self.state_transition.is_some()
    }

    // Param is passed by value, moved
    pub fn set_state_transition(&mut self, v: C2S_Transition) {
        self.state_transition = ::std::option::Option::Some(v);
    }

    pub fn get_state_transition(&self) -> C2S_Transition {
        self.state_transition.unwrap_or(C2S_Transition::C2S_NO_CHANGE)
    }

    fn get_state_transition_for_reflect(&self) -> &::std::option::Option<C2S_Transition> {
        &self.state_transition
    }

    fn mut_state_transition_for_reflect(&mut self) -> &mut ::std::option::Option<C2S_Transition> {
        &mut self.state_transition
    }

    // optional uint64 upload_sync = 4;

    pub fn clear_upload_sync(&mut self) {
        self.upload_sync = ::std::option::Option::None;
    }

    pub fn has_upload_sync(&self) -> bool {
        self.upload_sync.is_some()
    }

    // Param is passed by value, moved
    pub fn set_upload_sync(&mut self, v: u64) {
        self.upload_sync = ::std::option::Option::Some(v);
    }

    pub fn get_upload_sync(&self) -> u64 {
        self.upload_sync.unwrap_or(0)
    }

    fn get_upload_sync_for_reflect(&self) -> &::std::option::Option<u64> {
        &self.upload_sync
    }

    fn mut_upload_sync_for_reflect(&mut self) -> &mut ::std::option::Option<u64> {
        &mut self.upload_sync
    }

    // repeated string failed_decoys = 10;

    pub fn clear_failed_decoys(&mut self) {
        self.failed_decoys.clear();
    }

    // Param is passed by value, moved
    pub fn set_failed_decoys(&mut self, v: ::protobuf::RepeatedField<::std::string::String>) {
        self.failed_decoys = v;
    }

    // Mutable pointer to the field.
    pub fn mut_failed_decoys(&mut self) -> &mut ::protobuf::RepeatedField<::std::string::String> {
        &mut self.failed_decoys
    }

    // Take field
    pub fn take_failed_decoys(&mut self) -> ::protobuf::RepeatedField<::std::string::String> {
        ::std::mem::replace(&mut self.failed_decoys, ::protobuf::RepeatedField::new())
    }

    pub fn get_failed_decoys(&self) -> &[::std::string::String] {
        &self.failed_decoys
    }

    fn get_failed_decoys_for_reflect(&self) -> &::protobuf::RepeatedField<::std::string::String> {
        &self.failed_decoys
    }

    fn mut_failed_decoys_for_reflect(&mut self) -> &mut ::protobuf::RepeatedField<::std::string::String> {
        &mut self.failed_decoys
    }

    // optional .tapdance.SessionStats stats = 11;

    pub fn clear_stats(&mut self) {
        self.stats.clear();
    }

    pub fn has_stats(&self) -> bool {
        self.stats.is_some()
    }

    // Param is passed by value, moved
    pub fn set_stats(&mut self, v: SessionStats) {
        self.stats = ::protobuf::SingularPtrField::some(v);
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_stats(&mut self) -> &mut SessionStats {
        if self.stats.is_none() {
            self.stats.set_default();
        }
        self.stats.as_mut().unwrap()
    }

    // Take field
    pub fn take_stats(&mut self) -> SessionStats {
        self.stats.take().unwrap_or_else(|| SessionStats::new())
    }

    pub fn get_stats(&self) -> &SessionStats {
        self.stats.as_ref().unwrap_or_else(|| SessionStats::default_instance())
    }

    fn get_stats_for_reflect(&self) -> &::protobuf::SingularPtrField<SessionStats> {
        &self.stats
    }

    fn mut_stats_for_reflect(&mut self) -> &mut ::protobuf::SingularPtrField<SessionStats> {
        &mut self.stats
    }

    // optional string covert_address = 20;

    pub fn clear_covert_address(&mut self) {
        self.covert_address.clear();
    }

    pub fn has_covert_address(&self) -> bool {
        self.covert_address.is_some()
    }

    // Param is passed by value, moved
    pub fn set_covert_address(&mut self, v: ::std::string::String) {
        self.covert_address = ::protobuf::SingularField::some(v);
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_covert_address(&mut self) -> &mut ::std::string::String {
        if self.covert_address.is_none() {
            self.covert_address.set_default();
        }
        self.covert_address.as_mut().unwrap()
    }

    // Take field
    pub fn take_covert_address(&mut self) -> ::std::string::String {
        self.covert_address.take().unwrap_or_else(|| ::std::string::String::new())
    }

    pub fn get_covert_address(&self) -> &str {
        match self.covert_address.as_ref() {
            Some(v) => &v,
            None => "",
        }
    }

    fn get_covert_address_for_reflect(&self) -> &::protobuf::SingularField<::std::string::String> {
        &self.covert_address
    }

    fn mut_covert_address_for_reflect(&mut self) -> &mut ::protobuf::SingularField<::std::string::String> {
        &mut self.covert_address
    }

    // optional string masked_decoy_server_name = 21;

    pub fn clear_masked_decoy_server_name(&mut self) {
        self.masked_decoy_server_name.clear();
    }

    pub fn has_masked_decoy_server_name(&self) -> bool {
        self.masked_decoy_server_name.is_some()
    }

    // Param is passed by value, moved
    pub fn set_masked_decoy_server_name(&mut self, v: ::std::string::String) {
        self.masked_decoy_server_name = ::protobuf::SingularField::some(v);
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_masked_decoy_server_name(&mut self) -> &mut ::std::string::String {
        if self.masked_decoy_server_name.is_none() {
            self.masked_decoy_server_name.set_default();
        }
        self.masked_decoy_server_name.as_mut().unwrap()
    }

    // Take field
    pub fn take_masked_decoy_server_name(&mut self) -> ::std::string::String {
        self.masked_decoy_server_name.take().unwrap_or_else(|| ::std::string::String::new())
    }

    pub fn get_masked_decoy_server_name(&self) -> &str {
        match self.masked_decoy_server_name.as_ref() {
            Some(v) => &v,
            None => "",
        }
    }

    fn get_masked_decoy_server_name_for_reflect(&self) -> &::protobuf::SingularField<::std::string::String> {
        &self.masked_decoy_server_name
    }

    fn mut_masked_decoy_server_name_for_reflect(&mut self) -> &mut ::protobuf::SingularField<::std::string::String> {
        &mut self.masked_decoy_server_name
    }

    // optional bytes padding = 100;

    pub fn clear_padding(&mut self) {
        self.padding.clear();
    }

    pub fn has_padding(&self) -> bool {
        self.padding.is_some()
    }

    // Param is passed by value, moved
    pub fn set_padding(&mut self, v: ::std::vec::Vec<u8>) {
        self.padding = ::protobuf::SingularField::some(v);
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_padding(&mut self) -> &mut ::std::vec::Vec<u8> {
        if self.padding.is_none() {
            self.padding.set_default();
        }
        self.padding.as_mut().unwrap()
    }

    // Take field
    pub fn take_padding(&mut self) -> ::std::vec::Vec<u8> {
        self.padding.take().unwrap_or_else(|| ::std::vec::Vec::new())
    }

    pub fn get_padding(&self) -> &[u8] {
        match self.padding.as_ref() {
            Some(v) => &v,
            None => &[],
        }
    }

    fn get_padding_for_reflect(&self) -> &::protobuf::SingularField<::std::vec::Vec<u8>> {
        &self.padding
    }

    fn mut_padding_for_reflect(&mut self) -> &mut ::protobuf::SingularField<::std::vec::Vec<u8>> {
        &mut self.padding
    }
}

impl ::protobuf::Message for ClientToStation {
    fn is_initialized(&self) -> bool {
        for v in &self.stats {
            if !v.is_initialized() {
                return false;
            }
        };
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream) -> ::protobuf::ProtobufResult<()> {
        while !is.eof()? {
            let (field_number, wire_type) = is.read_tag_unpack()?;
            match field_number {
                1 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_uint32()?;
                    self.protocol_version = ::std::option::Option::Some(tmp);
                },
                2 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_uint32()?;
                    self.decoy_list_generation = ::std::option::Option::Some(tmp);
                },
                3 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_enum()?;
                    self.state_transition = ::std::option::Option::Some(tmp);
                },
                4 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_uint64()?;
                    self.upload_sync = ::std::option::Option::Some(tmp);
                },
                10 => {
                    ::protobuf::rt::read_repeated_string_into(wire_type, is, &mut self.failed_decoys)?;
                },
                11 => {
                    ::protobuf::rt::read_singular_message_into(wire_type, is, &mut self.stats)?;
                },
                20 => {
                    ::protobuf::rt::read_singular_string_into(wire_type, is, &mut self.covert_address)?;
                },
                21 => {
                    ::protobuf::rt::read_singular_string_into(wire_type, is, &mut self.masked_decoy_server_name)?;
                },
                100 => {
                    ::protobuf::rt::read_singular_bytes_into(wire_type, is, &mut self.padding)?;
                },
                _ => {
                    ::protobuf::rt::read_unknown_or_skip_group(field_number, wire_type, is, self.mut_unknown_fields())?;
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u32 {
        let mut my_size = 0;
        if let Some(v) = self.protocol_version {
            my_size += ::protobuf::rt::value_size(1, v, ::protobuf::wire_format::WireTypeVarint);
        }
        if let Some(v) = self.decoy_list_generation {
            my_size += ::protobuf::rt::value_size(2, v, ::protobuf::wire_format::WireTypeVarint);
        }
        if let Some(v) = self.state_transition {
            my_size += ::protobuf::rt::enum_size(3, v);
        }
        if let Some(v) = self.upload_sync {
            my_size += ::protobuf::rt::value_size(4, v, ::protobuf::wire_format::WireTypeVarint);
        }
        for value in &self.failed_decoys {
            my_size += ::protobuf::rt::string_size(10, &value);
        };
        if let Some(ref v) = self.stats.as_ref() {
            let len = v.compute_size();
            my_size += 1 + ::protobuf::rt::compute_raw_varint32_size(len) + len;
        }
        if let Some(ref v) = self.covert_address.as_ref() {
            my_size += ::protobuf::rt::string_size(20, &v);
        }
        if let Some(ref v) = self.masked_decoy_server_name.as_ref() {
            my_size += ::protobuf::rt::string_size(21, &v);
        }
        if let Some(ref v) = self.padding.as_ref() {
            my_size += ::protobuf::rt::bytes_size(100, &v);
        }
        my_size += ::protobuf::rt::unknown_fields_size(self.get_unknown_fields());
        self.cached_size.set(my_size);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream) -> ::protobuf::ProtobufResult<()> {
        if let Some(v) = self.protocol_version {
            os.write_uint32(1, v)?;
        }
        if let Some(v) = self.decoy_list_generation {
            os.write_uint32(2, v)?;
        }
        if let Some(v) = self.state_transition {
            os.write_enum(3, v.value())?;
        }
        if let Some(v) = self.upload_sync {
            os.write_uint64(4, v)?;
        }
        for v in &self.failed_decoys {
            os.write_string(10, &v)?;
        };
        if let Some(ref v) = self.stats.as_ref() {
            os.write_tag(11, ::protobuf::wire_format::WireTypeLengthDelimited)?;
            os.write_raw_varint32(v.get_cached_size())?;
            v.write_to_with_cached_sizes(os)?;
        }
        if let Some(ref v) = self.covert_address.as_ref() {
            os.write_string(20, &v)?;
        }
        if let Some(ref v) = self.masked_decoy_server_name.as_ref() {
            os.write_string(21, &v)?;
        }
        if let Some(ref v) = self.padding.as_ref() {
            os.write_bytes(100, &v)?;
        }
        os.write_unknown_fields(self.get_unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn get_cached_size(&self) -> u32 {
        self.cached_size.get()
    }

    fn get_unknown_fields(&self) -> &::protobuf::UnknownFields {
        &self.unknown_fields
    }

    fn mut_unknown_fields(&mut self) -> &mut ::protobuf::UnknownFields {
        &mut self.unknown_fields
    }

    fn as_any(&self) -> &::std::any::Any {
        self as &::std::any::Any
    }
    fn as_any_mut(&mut self) -> &mut ::std::any::Any {
        self as &mut ::std::any::Any
    }
    fn into_any(self: Box<Self>) -> ::std::boxed::Box<::std::any::Any> {
        self
    }

    fn descriptor(&self) -> &'static ::protobuf::reflect::MessageDescriptor {
        ::protobuf::MessageStatic::descriptor_static(None::<Self>)
    }
}

impl ::protobuf::MessageStatic for ClientToStation {
    fn new() -> ClientToStation {
        ClientToStation::new()
    }

    fn descriptor_static(_: ::std::option::Option<ClientToStation>) -> &'static ::protobuf::reflect::MessageDescriptor {
        static mut descriptor: ::protobuf::lazy::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const ::protobuf::reflect::MessageDescriptor,
        };
        unsafe {
            descriptor.get(|| {
                let mut fields = ::std::vec::Vec::new();
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeUint32>(
                    "protocol_version",
                    ClientToStation::get_protocol_version_for_reflect,
                    ClientToStation::mut_protocol_version_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeUint32>(
                    "decoy_list_generation",
                    ClientToStation::get_decoy_list_generation_for_reflect,
                    ClientToStation::mut_decoy_list_generation_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeEnum<C2S_Transition>>(
                    "state_transition",
                    ClientToStation::get_state_transition_for_reflect,
                    ClientToStation::mut_state_transition_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeUint64>(
                    "upload_sync",
                    ClientToStation::get_upload_sync_for_reflect,
                    ClientToStation::mut_upload_sync_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_repeated_field_accessor::<_, ::protobuf::types::ProtobufTypeString>(
                    "failed_decoys",
                    ClientToStation::get_failed_decoys_for_reflect,
                    ClientToStation::mut_failed_decoys_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_singular_ptr_field_accessor::<_, ::protobuf::types::ProtobufTypeMessage<SessionStats>>(
                    "stats",
                    ClientToStation::get_stats_for_reflect,
                    ClientToStation::mut_stats_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_singular_field_accessor::<_, ::protobuf::types::ProtobufTypeString>(
                    "covert_address",
                    ClientToStation::get_covert_address_for_reflect,
                    ClientToStation::mut_covert_address_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_singular_field_accessor::<_, ::protobuf::types::ProtobufTypeString>(
                    "masked_decoy_server_name",
                    ClientToStation::get_masked_decoy_server_name_for_reflect,
                    ClientToStation::mut_masked_decoy_server_name_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_singular_field_accessor::<_, ::protobuf::types::ProtobufTypeBytes>(
                    "padding",
                    ClientToStation::get_padding_for_reflect,
                    ClientToStation::mut_padding_for_reflect,
                ));
                ::protobuf::reflect::MessageDescriptor::new::<ClientToStation>(
                    "ClientToStation",
                    fields,
                    file_descriptor_proto()
                )
            })
        }
    }
}

impl ::protobuf::Clear for ClientToStation {
    fn clear(&mut self) {
        self.clear_protocol_version();
        self.clear_decoy_list_generation();
        self.clear_state_transition();
        self.clear_upload_sync();
        self.clear_failed_decoys();
        self.clear_stats();
        self.clear_covert_address();
        self.clear_masked_decoy_server_name();
        self.clear_padding();
        self.unknown_fields.clear();
    }
}

impl ::std::fmt::Debug for ClientToStation {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for ClientToStation {
    fn as_ref(&self) -> ::protobuf::reflect::ProtobufValueRef {
        ::protobuf::reflect::ProtobufValueRef::Message(self)
    }
}

#[derive(PartialEq,Clone,Default)]
pub struct SessionStats {
    // message fields
    failed_decoys_amount: ::std::option::Option<u32>,
    total_time_to_connect: ::std::option::Option<u32>,
    rtt_to_station: ::std::option::Option<u32>,
    tls_to_decoy: ::std::option::Option<u32>,
    tcp_to_decoy: ::std::option::Option<u32>,
    // special fields
    unknown_fields: ::protobuf::UnknownFields,
    cached_size: ::protobuf::CachedSize,
}

// see codegen.rs for the explanation why impl Sync explicitly
unsafe impl ::std::marker::Sync for SessionStats {}

impl SessionStats {
    pub fn new() -> SessionStats {
        ::std::default::Default::default()
    }

    pub fn default_instance() -> &'static SessionStats {
        static mut instance: ::protobuf::lazy::Lazy<SessionStats> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const SessionStats,
        };
        unsafe {
            instance.get(SessionStats::new)
        }
    }

    // optional uint32 failed_decoys_amount = 20;

    pub fn clear_failed_decoys_amount(&mut self) {
        self.failed_decoys_amount = ::std::option::Option::None;
    }

    pub fn has_failed_decoys_amount(&self) -> bool {
        self.failed_decoys_amount.is_some()
    }

    // Param is passed by value, moved
    pub fn set_failed_decoys_amount(&mut self, v: u32) {
        self.failed_decoys_amount = ::std::option::Option::Some(v);
    }

    pub fn get_failed_decoys_amount(&self) -> u32 {
        self.failed_decoys_amount.unwrap_or(0)
    }

    fn get_failed_decoys_amount_for_reflect(&self) -> &::std::option::Option<u32> {
        &self.failed_decoys_amount
    }

    fn mut_failed_decoys_amount_for_reflect(&mut self) -> &mut ::std::option::Option<u32> {
        &mut self.failed_decoys_amount
    }

    // optional uint32 total_time_to_connect = 31;

    pub fn clear_total_time_to_connect(&mut self) {
        self.total_time_to_connect = ::std::option::Option::None;
    }

    pub fn has_total_time_to_connect(&self) -> bool {
        self.total_time_to_connect.is_some()
    }

    // Param is passed by value, moved
    pub fn set_total_time_to_connect(&mut self, v: u32) {
        self.total_time_to_connect = ::std::option::Option::Some(v);
    }

    pub fn get_total_time_to_connect(&self) -> u32 {
        self.total_time_to_connect.unwrap_or(0)
    }

    fn get_total_time_to_connect_for_reflect(&self) -> &::std::option::Option<u32> {
        &self.total_time_to_connect
    }

    fn mut_total_time_to_connect_for_reflect(&mut self) -> &mut ::std::option::Option<u32> {
        &mut self.total_time_to_connect
    }

    // optional uint32 rtt_to_station = 33;

    pub fn clear_rtt_to_station(&mut self) {
        self.rtt_to_station = ::std::option::Option::None;
    }

    pub fn has_rtt_to_station(&self) -> bool {
        self.rtt_to_station.is_some()
    }

    // Param is passed by value, moved
    pub fn set_rtt_to_station(&mut self, v: u32) {
        self.rtt_to_station = ::std::option::Option::Some(v);
    }

    pub fn get_rtt_to_station(&self) -> u32 {
        self.rtt_to_station.unwrap_or(0)
    }

    fn get_rtt_to_station_for_reflect(&self) -> &::std::option::Option<u32> {
        &self.rtt_to_station
    }

    fn mut_rtt_to_station_for_reflect(&mut self) -> &mut ::std::option::Option<u32> {
        &mut self.rtt_to_station
    }

    // optional uint32 tls_to_decoy = 38;

    pub fn clear_tls_to_decoy(&mut self) {
        self.tls_to_decoy = ::std::option::Option::None;
    }

    pub fn has_tls_to_decoy(&self) -> bool {
        self.tls_to_decoy.is_some()
    }

    // Param is passed by value, moved
    pub fn set_tls_to_decoy(&mut self, v: u32) {
        self.tls_to_decoy = ::std::option::Option::Some(v);
    }

    pub fn get_tls_to_decoy(&self) -> u32 {
        self.tls_to_decoy.unwrap_or(0)
    }

    fn get_tls_to_decoy_for_reflect(&self) -> &::std::option::Option<u32> {
        &self.tls_to_decoy
    }

    fn mut_tls_to_decoy_for_reflect(&mut self) -> &mut ::std::option::Option<u32> {
        &mut self.tls_to_decoy
    }

    // optional uint32 tcp_to_decoy = 39;

    pub fn clear_tcp_to_decoy(&mut self) {
        self.tcp_to_decoy = ::std::option::Option::None;
    }

    pub fn has_tcp_to_decoy(&self) -> bool {
        self.tcp_to_decoy.is_some()
    }

    // Param is passed by value, moved
    pub fn set_tcp_to_decoy(&mut self, v: u32) {
        self.tcp_to_decoy = ::std::option::Option::Some(v);
    }

    pub fn get_tcp_to_decoy(&self) -> u32 {
        self.tcp_to_decoy.unwrap_or(0)
    }

    fn get_tcp_to_decoy_for_reflect(&self) -> &::std::option::Option<u32> {
        &self.tcp_to_decoy
    }

    fn mut_tcp_to_decoy_for_reflect(&mut self) -> &mut ::std::option::Option<u32> {
        &mut self.tcp_to_decoy
    }
}

impl ::protobuf::Message for SessionStats {
    fn is_initialized(&self) -> bool {
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream) -> ::protobuf::ProtobufResult<()> {
        while !is.eof()? {
            let (field_number, wire_type) = is.read_tag_unpack()?;
            match field_number {
                20 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_uint32()?;
                    self.failed_decoys_amount = ::std::option::Option::Some(tmp);
                },
                31 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_uint32()?;
                    self.total_time_to_connect = ::std::option::Option::Some(tmp);
                },
                33 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_uint32()?;
                    self.rtt_to_station = ::std::option::Option::Some(tmp);
                },
                38 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_uint32()?;
                    self.tls_to_decoy = ::std::option::Option::Some(tmp);
                },
                39 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_uint32()?;
                    self.tcp_to_decoy = ::std::option::Option::Some(tmp);
                },
                _ => {
                    ::protobuf::rt::read_unknown_or_skip_group(field_number, wire_type, is, self.mut_unknown_fields())?;
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u32 {
        let mut my_size = 0;
        if let Some(v) = self.failed_decoys_amount {
            my_size += ::protobuf::rt::value_size(20, v, ::protobuf::wire_format::WireTypeVarint);
        }
        if let Some(v) = self.total_time_to_connect {
            my_size += ::protobuf::rt::value_size(31, v, ::protobuf::wire_format::WireTypeVarint);
        }
        if let Some(v) = self.rtt_to_station {
            my_size += ::protobuf::rt::value_size(33, v, ::protobuf::wire_format::WireTypeVarint);
        }
        if let Some(v) = self.tls_to_decoy {
            my_size += ::protobuf::rt::value_size(38, v, ::protobuf::wire_format::WireTypeVarint);
        }
        if let Some(v) = self.tcp_to_decoy {
            my_size += ::protobuf::rt::value_size(39, v, ::protobuf::wire_format::WireTypeVarint);
        }
        my_size += ::protobuf::rt::unknown_fields_size(self.get_unknown_fields());
        self.cached_size.set(my_size);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream) -> ::protobuf::ProtobufResult<()> {
        if let Some(v) = self.failed_decoys_amount {
            os.write_uint32(20, v)?;
        }
        if let Some(v) = self.total_time_to_connect {
            os.write_uint32(31, v)?;
        }
        if let Some(v) = self.rtt_to_station {
            os.write_uint32(33, v)?;
        }
        if let Some(v) = self.tls_to_decoy {
            os.write_uint32(38, v)?;
        }
        if let Some(v) = self.tcp_to_decoy {
            os.write_uint32(39, v)?;
        }
        os.write_unknown_fields(self.get_unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn get_cached_size(&self) -> u32 {
        self.cached_size.get()
    }

    fn get_unknown_fields(&self) -> &::protobuf::UnknownFields {
        &self.unknown_fields
    }

    fn mut_unknown_fields(&mut self) -> &mut ::protobuf::UnknownFields {
        &mut self.unknown_fields
    }

    fn as_any(&self) -> &::std::any::Any {
        self as &::std::any::Any
    }
    fn as_any_mut(&mut self) -> &mut ::std::any::Any {
        self as &mut ::std::any::Any
    }
    fn into_any(self: Box<Self>) -> ::std::boxed::Box<::std::any::Any> {
        self
    }

    fn descriptor(&self) -> &'static ::protobuf::reflect::MessageDescriptor {
        ::protobuf::MessageStatic::descriptor_static(None::<Self>)
    }
}

impl ::protobuf::MessageStatic for SessionStats {
    fn new() -> SessionStats {
        SessionStats::new()
    }

    fn descriptor_static(_: ::std::option::Option<SessionStats>) -> &'static ::protobuf::reflect::MessageDescriptor {
        static mut descriptor: ::protobuf::lazy::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const ::protobuf::reflect::MessageDescriptor,
        };
        unsafe {
            descriptor.get(|| {
                let mut fields = ::std::vec::Vec::new();
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeUint32>(
                    "failed_decoys_amount",
                    SessionStats::get_failed_decoys_amount_for_reflect,
                    SessionStats::mut_failed_decoys_amount_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeUint32>(
                    "total_time_to_connect",
                    SessionStats::get_total_time_to_connect_for_reflect,
                    SessionStats::mut_total_time_to_connect_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeUint32>(
                    "rtt_to_station",
                    SessionStats::get_rtt_to_station_for_reflect,
                    SessionStats::mut_rtt_to_station_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeUint32>(
                    "tls_to_decoy",
                    SessionStats::get_tls_to_decoy_for_reflect,
                    SessionStats::mut_tls_to_decoy_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeUint32>(
                    "tcp_to_decoy",
                    SessionStats::get_tcp_to_decoy_for_reflect,
                    SessionStats::mut_tcp_to_decoy_for_reflect,
                ));
                ::protobuf::reflect::MessageDescriptor::new::<SessionStats>(
                    "SessionStats",
                    fields,
                    file_descriptor_proto()
                )
            })
        }
    }
}

impl ::protobuf::Clear for SessionStats {
    fn clear(&mut self) {
        self.clear_failed_decoys_amount();
        self.clear_total_time_to_connect();
        self.clear_rtt_to_station();
        self.clear_tls_to_decoy();
        self.clear_tcp_to_decoy();
        self.unknown_fields.clear();
    }
}

impl ::std::fmt::Debug for SessionStats {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for SessionStats {
    fn as_ref(&self) -> ::protobuf::reflect::ProtobufValueRef {
        ::protobuf::reflect::ProtobufValueRef::Message(self)
    }
}

#[derive(Clone,PartialEq,Eq,Debug,Hash)]
pub enum KeyType {
    AES_GCM_128 = 90,
    AES_GCM_256 = 91,
}

impl ::protobuf::ProtobufEnum for KeyType {
    fn value(&self) -> i32 {
        *self as i32
    }

    fn from_i32(value: i32) -> ::std::option::Option<KeyType> {
        match value {
            90 => ::std::option::Option::Some(KeyType::AES_GCM_128),
            91 => ::std::option::Option::Some(KeyType::AES_GCM_256),
            _ => ::std::option::Option::None
        }
    }

    fn values() -> &'static [Self] {
        static values: &'static [KeyType] = &[
            KeyType::AES_GCM_128,
            KeyType::AES_GCM_256,
        ];
        values
    }

    fn enum_descriptor_static(_: ::std::option::Option<KeyType>) -> &'static ::protobuf::reflect::EnumDescriptor {
        static mut descriptor: ::protobuf::lazy::Lazy<::protobuf::reflect::EnumDescriptor> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const ::protobuf::reflect::EnumDescriptor,
        };
        unsafe {
            descriptor.get(|| {
                ::protobuf::reflect::EnumDescriptor::new("KeyType", file_descriptor_proto())
            })
        }
    }
}

impl ::std::marker::Copy for KeyType {
}

impl ::protobuf::reflect::ProtobufValue for KeyType {
    fn as_ref(&self) -> ::protobuf::reflect::ProtobufValueRef {
        ::protobuf::reflect::ProtobufValueRef::Enum(self.descriptor())
    }
}

#[derive(Clone,PartialEq,Eq,Debug,Hash)]
pub enum C2S_Transition {
    C2S_NO_CHANGE = 0,
    C2S_SESSION_INIT = 1,
    C2S_SESSION_COVERT_INIT = 11,
    C2S_EXPECT_RECONNECT = 2,
    C2S_SESSION_CLOSE = 3,
    C2S_YIELD_UPLOAD = 4,
    C2S_ACQUIRE_UPLOAD = 5,
    C2S_EXPECT_UPLOADONLY_RECONN = 6,
    C2S_ERROR = 255,
}

impl ::protobuf::ProtobufEnum for C2S_Transition {
    fn value(&self) -> i32 {
        *self as i32
    }

    fn from_i32(value: i32) -> ::std::option::Option<C2S_Transition> {
        match value {
            0 => ::std::option::Option::Some(C2S_Transition::C2S_NO_CHANGE),
            1 => ::std::option::Option::Some(C2S_Transition::C2S_SESSION_INIT),
            11 => ::std::option::Option::Some(C2S_Transition::C2S_SESSION_COVERT_INIT),
            2 => ::std::option::Option::Some(C2S_Transition::C2S_EXPECT_RECONNECT),
            3 => ::std::option::Option::Some(C2S_Transition::C2S_SESSION_CLOSE),
            4 => ::std::option::Option::Some(C2S_Transition::C2S_YIELD_UPLOAD),
            5 => ::std::option::Option::Some(C2S_Transition::C2S_ACQUIRE_UPLOAD),
            6 => ::std::option::Option::Some(C2S_Transition::C2S_EXPECT_UPLOADONLY_RECONN),
            255 => ::std::option::Option::Some(C2S_Transition::C2S_ERROR),
            _ => ::std::option::Option::None
        }
    }

    fn values() -> &'static [Self] {
        static values: &'static [C2S_Transition] = &[
            C2S_Transition::C2S_NO_CHANGE,
            C2S_Transition::C2S_SESSION_INIT,
            C2S_Transition::C2S_SESSION_COVERT_INIT,
            C2S_Transition::C2S_EXPECT_RECONNECT,
            C2S_Transition::C2S_SESSION_CLOSE,
            C2S_Transition::C2S_YIELD_UPLOAD,
            C2S_Transition::C2S_ACQUIRE_UPLOAD,
            C2S_Transition::C2S_EXPECT_UPLOADONLY_RECONN,
            C2S_Transition::C2S_ERROR,
        ];
        values
    }

    fn enum_descriptor_static(_: ::std::option::Option<C2S_Transition>) -> &'static ::protobuf::reflect::EnumDescriptor {
        static mut descriptor: ::protobuf::lazy::Lazy<::protobuf::reflect::EnumDescriptor> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const ::protobuf::reflect::EnumDescriptor,
        };
        unsafe {
            descriptor.get(|| {
                ::protobuf::reflect::EnumDescriptor::new("C2S_Transition", file_descriptor_proto())
            })
        }
    }
}

impl ::std::marker::Copy for C2S_Transition {
}

impl ::protobuf::reflect::ProtobufValue for C2S_Transition {
    fn as_ref(&self) -> ::protobuf::reflect::ProtobufValueRef {
        ::protobuf::reflect::ProtobufValueRef::Enum(self.descriptor())
    }
}

#[derive(Clone,PartialEq,Eq,Debug,Hash)]
pub enum S2C_Transition {
    S2C_NO_CHANGE = 0,
    S2C_SESSION_INIT = 1,
    S2C_SESSION_COVERT_INIT = 11,
    S2C_CONFIRM_RECONNECT = 2,
    S2C_SESSION_CLOSE = 3,
    S2C_ERROR = 255,
}

impl ::protobuf::ProtobufEnum for S2C_Transition {
    fn value(&self) -> i32 {
        *self as i32
    }

    fn from_i32(value: i32) -> ::std::option::Option<S2C_Transition> {
        match value {
            0 => ::std::option::Option::Some(S2C_Transition::S2C_NO_CHANGE),
            1 => ::std::option::Option::Some(S2C_Transition::S2C_SESSION_INIT),
            11 => ::std::option::Option::Some(S2C_Transition::S2C_SESSION_COVERT_INIT),
            2 => ::std::option::Option::Some(S2C_Transition::S2C_CONFIRM_RECONNECT),
            3 => ::std::option::Option::Some(S2C_Transition::S2C_SESSION_CLOSE),
            255 => ::std::option::Option::Some(S2C_Transition::S2C_ERROR),
            _ => ::std::option::Option::None
        }
    }

    fn values() -> &'static [Self] {
        static values: &'static [S2C_Transition] = &[
            S2C_Transition::S2C_NO_CHANGE,
            S2C_Transition::S2C_SESSION_INIT,
            S2C_Transition::S2C_SESSION_COVERT_INIT,
            S2C_Transition::S2C_CONFIRM_RECONNECT,
            S2C_Transition::S2C_SESSION_CLOSE,
            S2C_Transition::S2C_ERROR,
        ];
        values
    }

    fn enum_descriptor_static(_: ::std::option::Option<S2C_Transition>) -> &'static ::protobuf::reflect::EnumDescriptor {
        static mut descriptor: ::protobuf::lazy::Lazy<::protobuf::reflect::EnumDescriptor> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const ::protobuf::reflect::EnumDescriptor,
        };
        unsafe {
            descriptor.get(|| {
                ::protobuf::reflect::EnumDescriptor::new("S2C_Transition", file_descriptor_proto())
            })
        }
    }
}

impl ::std::marker::Copy for S2C_Transition {
}

impl ::protobuf::reflect::ProtobufValue for S2C_Transition {
    fn as_ref(&self) -> ::protobuf::reflect::ProtobufValueRef {
        ::protobuf::reflect::ProtobufValueRef::Enum(self.descriptor())
    }
}

#[derive(Clone,PartialEq,Eq,Debug,Hash)]
pub enum ErrorReasonS2C {
    NO_ERROR = 0,
    COVERT_STREAM = 1,
    CLIENT_REPORTED = 2,
    CLIENT_PROTOCOL = 3,
    STATION_INTERNAL = 4,
    DECOY_OVERLOAD = 5,
    CLIENT_STREAM = 100,
    CLIENT_TIMEOUT = 101,
}

impl ::protobuf::ProtobufEnum for ErrorReasonS2C {
    fn value(&self) -> i32 {
        *self as i32
    }

    fn from_i32(value: i32) -> ::std::option::Option<ErrorReasonS2C> {
        match value {
            0 => ::std::option::Option::Some(ErrorReasonS2C::NO_ERROR),
            1 => ::std::option::Option::Some(ErrorReasonS2C::COVERT_STREAM),
            2 => ::std::option::Option::Some(ErrorReasonS2C::CLIENT_REPORTED),
            3 => ::std::option::Option::Some(ErrorReasonS2C::CLIENT_PROTOCOL),
            4 => ::std::option::Option::Some(ErrorReasonS2C::STATION_INTERNAL),
            5 => ::std::option::Option::Some(ErrorReasonS2C::DECOY_OVERLOAD),
            100 => ::std::option::Option::Some(ErrorReasonS2C::CLIENT_STREAM),
            101 => ::std::option::Option::Some(ErrorReasonS2C::CLIENT_TIMEOUT),
            _ => ::std::option::Option::None
        }
    }

    fn values() -> &'static [Self] {
        static values: &'static [ErrorReasonS2C] = &[
            ErrorReasonS2C::NO_ERROR,
            ErrorReasonS2C::COVERT_STREAM,
            ErrorReasonS2C::CLIENT_REPORTED,
            ErrorReasonS2C::CLIENT_PROTOCOL,
            ErrorReasonS2C::STATION_INTERNAL,
            ErrorReasonS2C::DECOY_OVERLOAD,
            ErrorReasonS2C::CLIENT_STREAM,
            ErrorReasonS2C::CLIENT_TIMEOUT,
        ];
        values
    }

    fn enum_descriptor_static(_: ::std::option::Option<ErrorReasonS2C>) -> &'static ::protobuf::reflect::EnumDescriptor {
        static mut descriptor: ::protobuf::lazy::Lazy<::protobuf::reflect::EnumDescriptor> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const ::protobuf::reflect::EnumDescriptor,
        };
        unsafe {
            descriptor.get(|| {
                ::protobuf::reflect::EnumDescriptor::new("ErrorReasonS2C", file_descriptor_proto())
            })
        }
    }
}

impl ::std::marker::Copy for ErrorReasonS2C {
}

impl ::protobuf::reflect::ProtobufValue for ErrorReasonS2C {
    fn as_ref(&self) -> ::protobuf::reflect::ProtobufValueRef {
        ::protobuf::reflect::ProtobufValueRef::Enum(self.descriptor())
    }
}

static file_descriptor_proto_data: &'static [u8] = b"\
    \n\x10signalling.proto\x12\x08tapdance\"6\n\x06PubKey\x12\x0b\n\x03key\
    \x18\x01\x20\x01(\x0c\x12\x1f\n\x04type\x18\x02\x20\x01(\x0e2\x11.tapdan\
    ce.KeyType\"\x87\x01\n\x0cTLSDecoySpec\x12\x10\n\x08hostname\x18\x01\x20\
    \x01(\t\x12\x10\n\x08ipv4addr\x18\x02\x20\x01(\x07\x12\x10\n\x08ipv6addr\
    \x18\x06\x20\x01(\x0c\x12\x20\n\x06pubkey\x18\x03\x20\x01(\x0b2\x10.tapd\
    ance.PubKey\x12\x0f\n\x07timeout\x18\x04\x20\x01(\r\x12\x0e\n\x06tcpwin\
    \x18\x05\x20\x01(\r\"s\n\nClientConf\x12'\n\ndecoy_list\x18\x01\x20\x01(\
    \x0b2\x13.tapdance.DecoyList\x12\x12\n\ngeneration\x18\x02\x20\x01(\r\
    \x12(\n\x0edefault_pubkey\x18\x03\x20\x01(\x0b2\x10.tapdance.PubKey\"7\n\
    \tDecoyList\x12*\n\ntls_decoys\x18\x01\x20\x03(\x0b2\x16.tapdance.TLSDec\
    oySpec\"\xf2\x01\n\x0fStationToClient\x12\x18\n\x10protocol_version\x18\
    \x01\x20\x01(\r\x122\n\x10state_transition\x18\x02\x20\x01(\x0e2\x18.tap\
    dance.S2C_Transition\x12)\n\x0bconfig_info\x18\x03\x20\x01(\x0b2\x14.tap\
    dance.ClientConf\x12,\n\nerr_reason\x18\x04\x20\x01(\x0e2\x18.tapdance.E\
    rrorReasonS2C\x12\x13\n\x0btmp_backoff\x18\x05\x20\x01(\r\x12\x12\n\nsta\
    tion_id\x18\x06\x20\x01(\t\x12\x0f\n\x07padding\x18d\x20\x01(\x0c\"\x9c\
    \x02\n\x0fClientToStation\x12\x18\n\x10protocol_version\x18\x01\x20\x01(\
    \r\x12\x1d\n\x15decoy_list_generation\x18\x02\x20\x01(\r\x122\n\x10state\
    _transition\x18\x03\x20\x01(\x0e2\x18.tapdance.C2S_Transition\x12\x13\n\
    \x0bupload_sync\x18\x04\x20\x01(\x04\x12\x15\n\rfailed_decoys\x18\n\x20\
    \x03(\t\x12%\n\x05stats\x18\x0b\x20\x01(\x0b2\x16.tapdance.SessionStats\
    \x12\x16\n\x0ecovert_address\x18\x14\x20\x01(\t\x12\x20\n\x18masked_deco\
    y_server_name\x18\x15\x20\x01(\t\x12\x0f\n\x07padding\x18d\x20\x01(\x0c\
    \"\x8f\x01\n\x0cSessionStats\x12\x1c\n\x14failed_decoys_amount\x18\x14\
    \x20\x01(\r\x12\x1d\n\x15total_time_to_connect\x18\x1f\x20\x01(\r\x12\
    \x16\n\x0ertt_to_station\x18!\x20\x01(\r\x12\x14\n\x0ctls_to_decoy\x18&\
    \x20\x01(\r\x12\x14\n\x0ctcp_to_decoy\x18'\x20\x01(\r*+\n\x07KeyType\x12\
    \x0f\n\x0bAES_GCM_128\x10Z\x12\x0f\n\x0bAES_GCM_256\x10[*\xe7\x01\n\x0eC\
    2S_Transition\x12\x11\n\rC2S_NO_CHANGE\x10\0\x12\x14\n\x10C2S_SESSION_IN\
    IT\x10\x01\x12\x1b\n\x17C2S_SESSION_COVERT_INIT\x10\x0b\x12\x18\n\x14C2S\
    _EXPECT_RECONNECT\x10\x02\x12\x15\n\x11C2S_SESSION_CLOSE\x10\x03\x12\x14\
    \n\x10C2S_YIELD_UPLOAD\x10\x04\x12\x16\n\x12C2S_ACQUIRE_UPLOAD\x10\x05\
    \x12\x20\n\x1cC2S_EXPECT_UPLOADONLY_RECONN\x10\x06\x12\x0e\n\tC2S_ERROR\
    \x10\xff\x01*\x98\x01\n\x0eS2C_Transition\x12\x11\n\rS2C_NO_CHANGE\x10\0\
    \x12\x14\n\x10S2C_SESSION_INIT\x10\x01\x12\x1b\n\x17S2C_SESSION_COVERT_I\
    NIT\x10\x0b\x12\x19\n\x15S2C_CONFIRM_RECONNECT\x10\x02\x12\x15\n\x11S2C_\
    SESSION_CLOSE\x10\x03\x12\x0e\n\tS2C_ERROR\x10\xff\x01*\xac\x01\n\x0eErr\
    orReasonS2C\x12\x0c\n\x08NO_ERROR\x10\0\x12\x11\n\rCOVERT_STREAM\x10\x01\
    \x12\x13\n\x0fCLIENT_REPORTED\x10\x02\x12\x13\n\x0fCLIENT_PROTOCOL\x10\
    \x03\x12\x14\n\x10STATION_INTERNAL\x10\x04\x12\x12\n\x0eDECOY_OVERLOAD\
    \x10\x05\x12\x11\n\rCLIENT_STREAM\x10d\x12\x12\n\x0eCLIENT_TIMEOUT\x10eJ\
    \xac8\n\x07\x12\x05\0\0\xc9\x01\x01\n\x08\n\x01\x02\x12\x03\x06\x08\x10\
    \n\n\n\x02\x05\0\x12\x04\x08\0\x0b\x01\n\n\n\x03\x05\0\x01\x12\x03\x08\
    \x05\x0c\n\x0b\n\x04\x05\0\x02\0\x12\x03\t\x04\x15\n\x0c\n\x05\x05\0\x02\
    \0\x01\x12\x03\t\x04\x0f\n\x0c\n\x05\x05\0\x02\0\x02\x12\x03\t\x12\x14\n\
    \x20\n\x04\x05\0\x02\x01\x12\x03\n\x04\x15\"\x13\x20not\x20supported\x20\
    atm\n\n\x0c\n\x05\x05\0\x02\x01\x01\x12\x03\n\x04\x0f\n\x0c\n\x05\x05\0\
    \x02\x01\x02\x12\x03\n\x12\x14\n\n\n\x02\x04\0\x12\x04\r\0\x12\x01\n\n\n\
    \x03\x04\0\x01\x12\x03\r\x08\x0e\n4\n\x04\x04\0\x02\0\x12\x03\x0f\x04\
    \x1b\x1a'\x20A\x20public\x20key,\x20as\x20used\x20by\x20the\x20station.\
    \n\n\x0c\n\x05\x04\0\x02\0\x04\x12\x03\x0f\x04\x0c\n\x0c\n\x05\x04\0\x02\
    \0\x05\x12\x03\x0f\r\x12\n\x0c\n\x05\x04\0\x02\0\x01\x12\x03\x0f\x13\x16\
    \n\x0c\n\x05\x04\0\x02\0\x03\x12\x03\x0f\x19\x1a\n\x0b\n\x04\x04\0\x02\
    \x01\x12\x03\x11\x04\x1e\n\x0c\n\x05\x04\0\x02\x01\x04\x12\x03\x11\x04\
    \x0c\n\x0c\n\x05\x04\0\x02\x01\x06\x12\x03\x11\r\x14\n\x0c\n\x05\x04\0\
    \x02\x01\x01\x12\x03\x11\x15\x19\n\x0c\n\x05\x04\0\x02\x01\x03\x12\x03\
    \x11\x1c\x1d\n\n\n\x02\x04\x01\x12\x04\x14\0:\x01\n\n\n\x03\x04\x01\x01\
    \x12\x03\x14\x08\x14\n\xa1\x01\n\x04\x04\x01\x02\0\x12\x03\x19\x04!\x1a\
    \x93\x01\x20The\x20hostname/SNI\x20to\x20use\x20for\x20this\x20host\n\n\
    \x20The\x20hostname\x20is\x20the\x20only\x20required\x20field,\x20althou\
    gh\x20other\n\x20fields\x20are\x20expected\x20to\x20be\x20present\x20in\
    \x20most\x20cases.\n\n\x0c\n\x05\x04\x01\x02\0\x04\x12\x03\x19\x04\x0c\n\
    \x0c\n\x05\x04\x01\x02\0\x05\x12\x03\x19\r\x13\n\x0c\n\x05\x04\x01\x02\0\
    \x01\x12\x03\x19\x14\x1c\n\x0c\n\x05\x04\x01\x02\0\x03\x12\x03\x19\x1f\
    \x20\n\xf7\x01\n\x04\x04\x01\x02\x01\x12\x03\x20\x04\"\x1a\xe9\x01\x20Th\
    e\x2032-bit\x20ipv4\x20address,\x20in\x20network\x20byte\x20order\n\n\
    \x20If\x20the\x20IPv4\x20address\x20is\x20absent,\x20then\x20it\x20may\
    \x20be\x20resolved\x20via\n\x20DNS\x20by\x20the\x20client,\x20or\x20the\
    \x20client\x20may\x20discard\x20this\x20decoy\x20spec\n\x20if\x20local\
    \x20DNS\x20is\x20untrusted,\x20or\x20the\x20service\x20may\x20be\x20mult\
    ihomed.\n\n\x0c\n\x05\x04\x01\x02\x01\x04\x12\x03\x20\x04\x0c\n\x0c\n\
    \x05\x04\x01\x02\x01\x05\x12\x03\x20\r\x14\n\x0c\n\x05\x04\x01\x02\x01\
    \x01\x12\x03\x20\x15\x1d\n\x0c\n\x05\x04\x01\x02\x01\x03\x12\x03\x20\x20\
    !\n>\n\x04\x04\x01\x02\x02\x12\x03#\x04\x20\x1a1\x20The\x20128-bit\x20ip\
    v6\x20address,\x20in\x20network\x20byte\x20order\n\n\x0c\n\x05\x04\x01\
    \x02\x02\x04\x12\x03#\x04\x0c\n\x0c\n\x05\x04\x01\x02\x02\x05\x12\x03#\r\
    \x12\n\x0c\n\x05\x04\x01\x02\x02\x01\x12\x03#\x13\x1b\n\x0c\n\x05\x04\
    \x01\x02\x02\x03\x12\x03#\x1e\x1f\n\x91\x01\n\x04\x04\x01\x02\x03\x12\
    \x03)\x04\x1f\x1a\x83\x01\x20The\x20Tapdance\x20station\x20public\x20key\
    \x20to\x20use\x20when\x20contacting\x20this\n\x20decoy\n\n\x20If\x20omit\
    ted,\x20the\x20default\x20station\x20public\x20key\x20(if\x20any)\x20is\
    \x20used.\n\n\x0c\n\x05\x04\x01\x02\x03\x04\x12\x03)\x04\x0c\n\x0c\n\x05\
    \x04\x01\x02\x03\x06\x12\x03)\r\x13\n\x0c\n\x05\x04\x01\x02\x03\x01\x12\
    \x03)\x14\x1a\n\x0c\n\x05\x04\x01\x02\x03\x03\x12\x03)\x1d\x1e\n\xee\x01\
    \n\x04\x04\x01\x02\x04\x12\x030\x04\x20\x1a\xe0\x01\x20The\x20maximum\
    \x20duration,\x20in\x20milliseconds,\x20to\x20maintain\x20an\x20open\n\
    \x20connection\x20to\x20this\x20decoy\x20(because\x20the\x20decoy\x20may\
    \x20close\x20the\n\x20connection\x20itself\x20after\x20this\x20length\
    \x20of\x20time)\n\n\x20If\x20omitted,\x20a\x20default\x20of\x2030,000\
    \x20milliseconds\x20is\x20assumed.\n\n\x0c\n\x05\x04\x01\x02\x04\x04\x12\
    \x030\x04\x0c\n\x0c\n\x05\x04\x01\x02\x04\x05\x12\x030\r\x13\n\x0c\n\x05\
    \x04\x01\x02\x04\x01\x12\x030\x14\x1b\n\x0c\n\x05\x04\x01\x02\x04\x03\
    \x12\x030\x1e\x1f\n\xb0\x02\n\x04\x04\x01\x02\x05\x12\x039\x04\x1f\x1a\
    \xa2\x02\x20The\x20maximum\x20TCP\x20window\x20size\x20to\x20attempt\x20\
    to\x20use\x20for\x20this\x20decoy.\n\n\x20If\x20omitted,\x20a\x20default\
    \x20of\x2015360\x20is\x20assumed.\n\n\x20TODO:\x20the\x20default\x20is\
    \x20based\x20on\x20the\x20current\x20heuristic\x20of\x20only\n\x20using\
    \x20decoys\x20that\x20permit\x20windows\x20of\x2015KB\x20or\x20larger.\
    \x20\x20If\x20this\n\x20heuristic\x20changes,\x20then\x20this\x20default\
    \x20doesn't\x20make\x20sense.\n\n\x0c\n\x05\x04\x01\x02\x05\x04\x12\x039\
    \x04\x0c\n\x0c\n\x05\x04\x01\x02\x05\x05\x12\x039\r\x13\n\x0c\n\x05\x04\
    \x01\x02\x05\x01\x12\x039\x14\x1a\n\x0c\n\x05\x04\x01\x02\x05\x03\x12\
    \x039\x1d\x1e\n\n\n\x02\x04\x02\x12\x04Q\0U\x01\n\n\n\x03\x04\x02\x01\
    \x12\x03Q\x08\x12\n\x0b\n\x04\x04\x02\x02\0\x12\x03R\x04&\n\x0c\n\x05\
    \x04\x02\x02\0\x04\x12\x03R\x04\x0c\n\x0c\n\x05\x04\x02\x02\0\x06\x12\
    \x03R\r\x16\n\x0c\n\x05\x04\x02\x02\0\x01\x12\x03R\x17!\n\x0c\n\x05\x04\
    \x02\x02\0\x03\x12\x03R$%\n\x0b\n\x04\x04\x02\x02\x01\x12\x03S\x04#\n\
    \x0c\n\x05\x04\x02\x02\x01\x04\x12\x03S\x04\x0c\n\x0c\n\x05\x04\x02\x02\
    \x01\x05\x12\x03S\r\x13\n\x0c\n\x05\x04\x02\x02\x01\x01\x12\x03S\x14\x1e\
    \n\x0c\n\x05\x04\x02\x02\x01\x03\x12\x03S!\"\n\x0b\n\x04\x04\x02\x02\x02\
    \x12\x03T\x04'\n\x0c\n\x05\x04\x02\x02\x02\x04\x12\x03T\x04\x0c\n\x0c\n\
    \x05\x04\x02\x02\x02\x06\x12\x03T\r\x13\n\x0c\n\x05\x04\x02\x02\x02\x01\
    \x12\x03T\x14\"\n\x0c\n\x05\x04\x02\x02\x02\x03\x12\x03T%&\n\n\n\x02\x04\
    \x03\x12\x04W\0Y\x01\n\n\n\x03\x04\x03\x01\x12\x03W\x08\x11\n\x0b\n\x04\
    \x04\x03\x02\0\x12\x03X\x04)\n\x0c\n\x05\x04\x03\x02\0\x04\x12\x03X\x04\
    \x0c\n\x0c\n\x05\x04\x03\x02\0\x06\x12\x03X\r\x19\n\x0c\n\x05\x04\x03\
    \x02\0\x01\x12\x03X\x1a$\n\x0c\n\x05\x04\x03\x02\0\x03\x12\x03X'(\n-\n\
    \x02\x05\x01\x12\x04\\\0f\x01\x1a!\x20State\x20transitions\x20of\x20the\
    \x20client\n\n\n\n\x03\x05\x01\x01\x12\x03\\\x05\x13\n\x0b\n\x04\x05\x01\
    \x02\0\x12\x03]\x04\x16\n\x0c\n\x05\x05\x01\x02\0\x01\x12\x03]\x04\x11\n\
    \x0c\n\x05\x05\x01\x02\0\x02\x12\x03]\x14\x15\n\"\n\x04\x05\x01\x02\x01\
    \x12\x03^\x04\x19\"\x15\x20connect\x20me\x20to\x20squid\n\n\x0c\n\x05\
    \x05\x01\x02\x01\x01\x12\x03^\x04\x14\n\x0c\n\x05\x05\x01\x02\x01\x02\
    \x12\x03^\x17\x18\n,\n\x04\x05\x01\x02\x02\x12\x03_\x04!\"\x1f\x20connec\
    t\x20me\x20to\x20provided\x20covert\n\n\x0c\n\x05\x05\x01\x02\x02\x01\
    \x12\x03_\x04\x1b\n\x0c\n\x05\x05\x01\x02\x02\x02\x12\x03_\x1e\x20\n\x0b\
    \n\x04\x05\x01\x02\x03\x12\x03`\x04\x1d\n\x0c\n\x05\x05\x01\x02\x03\x01\
    \x12\x03`\x04\x18\n\x0c\n\x05\x05\x01\x02\x03\x02\x12\x03`\x1b\x1c\n\x0b\
    \n\x04\x05\x01\x02\x04\x12\x03a\x04\x1a\n\x0c\n\x05\x05\x01\x02\x04\x01\
    \x12\x03a\x04\x15\n\x0c\n\x05\x05\x01\x02\x04\x02\x12\x03a\x18\x19\n\x0b\
    \n\x04\x05\x01\x02\x05\x12\x03b\x04\x19\n\x0c\n\x05\x05\x01\x02\x05\x01\
    \x12\x03b\x04\x14\n\x0c\n\x05\x05\x01\x02\x05\x02\x12\x03b\x17\x18\n\x0b\
    \n\x04\x05\x01\x02\x06\x12\x03c\x04\x1b\n\x0c\n\x05\x05\x01\x02\x06\x01\
    \x12\x03c\x04\x16\n\x0c\n\x05\x05\x01\x02\x06\x02\x12\x03c\x19\x1a\n\x0b\
    \n\x04\x05\x01\x02\x07\x12\x03d\x04%\n\x0c\n\x05\x05\x01\x02\x07\x01\x12\
    \x03d\x04\x20\n\x0c\n\x05\x05\x01\x02\x07\x02\x12\x03d#$\n\x0b\n\x04\x05\
    \x01\x02\x08\x12\x03e\x04\x14\n\x0c\n\x05\x05\x01\x02\x08\x01\x12\x03e\
    \x04\r\n\x0c\n\x05\x05\x01\x02\x08\x02\x12\x03e\x10\x13\n-\n\x02\x05\x02\
    \x12\x04i\0q\x01\x1a!\x20State\x20transitions\x20of\x20the\x20server\n\n\
    \n\n\x03\x05\x02\x01\x12\x03i\x05\x13\n\x0b\n\x04\x05\x02\x02\0\x12\x03j\
    \x04\x16\n\x0c\n\x05\x05\x02\x02\0\x01\x12\x03j\x04\x11\n\x0c\n\x05\x05\
    \x02\x02\0\x02\x12\x03j\x14\x15\n!\n\x04\x05\x02\x02\x01\x12\x03k\x04\
    \x19\"\x14\x20connected\x20to\x20squid\n\n\x0c\n\x05\x05\x02\x02\x01\x01\
    \x12\x03k\x04\x14\n\x0c\n\x05\x05\x02\x02\x01\x02\x12\x03k\x17\x18\n'\n\
    \x04\x05\x02\x02\x02\x12\x03l\x04!\"\x1a\x20connected\x20to\x20covert\
    \x20host\n\n\x0c\n\x05\x05\x02\x02\x02\x01\x12\x03l\x04\x1b\n\x0c\n\x05\
    \x05\x02\x02\x02\x02\x12\x03l\x1e\x20\n\x0b\n\x04\x05\x02\x02\x03\x12\
    \x03m\x04\x1e\n\x0c\n\x05\x05\x02\x02\x03\x01\x12\x03m\x04\x19\n\x0c\n\
    \x05\x05\x02\x02\x03\x02\x12\x03m\x1c\x1d\n\x0b\n\x04\x05\x02\x02\x04\
    \x12\x03n\x04\x1a\n\x0c\n\x05\x05\x02\x02\x04\x01\x12\x03n\x04\x15\n\x0c\
    \n\x05\x05\x02\x02\x04\x02\x12\x03n\x18\x19\nR\n\x04\x05\x02\x02\x05\x12\
    \x03p\x04\x14\x1aE\x20TODO\x20should\x20probably\x20also\x20allow\x20EXP\
    ECT_RECONNECT\x20here,\x20for\x20DittoTap\n\n\x0c\n\x05\x05\x02\x02\x05\
    \x01\x12\x03p\x04\r\n\x0c\n\x05\x05\x02\x02\x05\x02\x12\x03p\x10\x13\n6\
    \n\x02\x05\x03\x12\x04t\0~\x01\x1a*\x20Should\x20accompany\x20all\x20S2C\
    _ERROR\x20messages.\n\n\n\n\x03\x05\x03\x01\x12\x03t\x05\x13\n\x0b\n\x04\
    \x05\x03\x02\0\x12\x03u\x04\x11\n\x0c\n\x05\x05\x03\x02\0\x01\x12\x03u\
    \x04\x0c\n\x0c\n\x05\x05\x03\x02\0\x02\x12\x03u\x0f\x10\n)\n\x04\x05\x03\
    \x02\x01\x12\x03v\x04\x16\"\x1c\x20Squid\x20TCP\x20connection\x20broke\n\
    \n\x0c\n\x05\x05\x03\x02\x01\x01\x12\x03v\x04\x11\n\x0c\n\x05\x05\x03\
    \x02\x01\x02\x12\x03v\x14\x15\n6\n\x04\x05\x03\x02\x02\x12\x03w\x04\x18\
    \")\x20You\x20told\x20me\x20something\x20was\x20wrong,\x20client\n\n\x0c\
    \n\x05\x05\x03\x02\x02\x01\x12\x03w\x04\x13\n\x0c\n\x05\x05\x03\x02\x02\
    \x02\x12\x03w\x16\x17\n?\n\x04\x05\x03\x02\x03\x12\x03x\x04\x18\"2\x20Yo\
    u\x20messed\x20up,\x20client\x20(e.g.\x20sent\x20a\x20bad\x20protobuf)\n\
    \n\x0c\n\x05\x05\x03\x02\x03\x01\x12\x03x\x04\x13\n\x0c\n\x05\x05\x03\
    \x02\x03\x02\x12\x03x\x16\x17\n\x16\n\x04\x05\x03\x02\x04\x12\x03y\x04\
    \x19\"\t\x20I\x20broke\n\n\x0c\n\x05\x05\x03\x02\x04\x01\x12\x03y\x04\
    \x14\n\x0c\n\x05\x05\x03\x02\x04\x02\x12\x03y\x17\x18\nD\n\x04\x05\x03\
    \x02\x05\x12\x03z\x04\x17\"7\x20Everything's\x20fine,\x20but\x20don't\
    \x20use\x20this\x20decoy\x20right\x20now\n\n\x0c\n\x05\x05\x03\x02\x05\
    \x01\x12\x03z\x04\x12\n\x0c\n\x05\x05\x03\x02\x05\x02\x12\x03z\x15\x16\n\
    C\n\x04\x05\x03\x02\x06\x12\x03|\x04\x18\"6\x20My\x20stream\x20to\x20you\
    \x20broke.\x20(This\x20is\x20impossible\x20to\x20send)\n\n\x0c\n\x05\x05\
    \x03\x02\x06\x01\x12\x03|\x04\x11\n\x0c\n\x05\x05\x03\x02\x06\x02\x12\
    \x03|\x14\x17\n@\n\x04\x05\x03\x02\x07\x12\x03}\x04\x19\"3\x20You\x20nev\
    er\x20came\x20back.\x20(This\x20is\x20impossible\x20to\x20send)\n\n\x0c\
    \n\x05\x05\x03\x02\x07\x01\x12\x03}\x04\x12\n\x0c\n\x05\x05\x03\x02\x07\
    \x02\x12\x03}\x15\x18\n\x0c\n\x02\x04\x04\x12\x06\x80\x01\0\x97\x01\x01\
    \n\x0b\n\x03\x04\x04\x01\x12\x04\x80\x01\x08\x17\nO\n\x04\x04\x04\x02\0\
    \x12\x04\x82\x01\x04)\x1aA\x20Should\x20accompany\x20(at\x20least)\x20SE\
    SSION_INIT\x20and\x20CONFIRM_RECONNECT.\n\n\r\n\x05\x04\x04\x02\0\x04\
    \x12\x04\x82\x01\x04\x0c\n\r\n\x05\x04\x04\x02\0\x05\x12\x04\x82\x01\r\
    \x13\n\r\n\x05\x04\x04\x02\0\x01\x12\x04\x82\x01\x14$\n\r\n\x05\x04\x04\
    \x02\0\x03\x12\x04\x82\x01'(\nv\n\x04\x04\x04\x02\x01\x12\x04\x86\x01\
    \x041\x1ah\x20There\x20might\x20be\x20a\x20state\x20transition.\x20May\
    \x20be\x20absent;\x20absence\x20should\x20be\n\x20treated\x20identically\
    \x20to\x20NO_CHANGE.\n\n\r\n\x05\x04\x04\x02\x01\x04\x12\x04\x86\x01\x04\
    \x0c\n\r\n\x05\x04\x04\x02\x01\x06\x12\x04\x86\x01\r\x1b\n\r\n\x05\x04\
    \x04\x02\x01\x01\x12\x04\x86\x01\x1c,\n\r\n\x05\x04\x04\x02\x01\x03\x12\
    \x04\x86\x01/0\nc\n\x04\x04\x04\x02\x02\x12\x04\x8a\x01\x04(\x1aU\x20The\
    \x20station\x20can\x20send\x20client\x20config\x20info\x20piggybacked\n\
    \x20on\x20any\x20message,\x20as\x20it\x20sees\x20fit\n\n\r\n\x05\x04\x04\
    \x02\x02\x04\x12\x04\x8a\x01\x04\x0c\n\r\n\x05\x04\x04\x02\x02\x06\x12\
    \x04\x8a\x01\r\x17\n\r\n\x05\x04\x04\x02\x02\x01\x12\x04\x8a\x01\x18#\n\
    \r\n\x05\x04\x04\x02\x02\x03\x12\x04\x8a\x01&'\nP\n\x04\x04\x04\x02\x03\
    \x12\x04\x8d\x01\x04+\x1aB\x20If\x20state_transition\x20==\x20S2C_ERROR,\
    \x20this\x20field\x20is\x20the\x20explanation.\n\n\r\n\x05\x04\x04\x02\
    \x03\x04\x12\x04\x8d\x01\x04\x0c\n\r\n\x05\x04\x04\x02\x03\x06\x12\x04\
    \x8d\x01\r\x1b\n\r\n\x05\x04\x04\x02\x03\x01\x12\x04\x8d\x01\x1c&\n\r\n\
    \x05\x04\x04\x02\x03\x03\x12\x04\x8d\x01)*\nQ\n\x04\x04\x04\x02\x04\x12\
    \x04\x90\x01\x04$\x1aC\x20Signals\x20client\x20to\x20stop\x20connecting\
    \x20for\x20following\x20amount\x20of\x20seconds\n\n\r\n\x05\x04\x04\x02\
    \x04\x04\x12\x04\x90\x01\x04\x0c\n\r\n\x05\x04\x04\x02\x04\x05\x12\x04\
    \x90\x01\r\x13\n\r\n\x05\x04\x04\x02\x04\x01\x12\x04\x90\x01\x14\x1f\n\r\
    \n\x05\x04\x04\x02\x04\x03\x12\x04\x90\x01\"#\nK\n\x04\x04\x04\x02\x05\
    \x12\x04\x93\x01\x04#\x1a=\x20Sent\x20in\x20SESSION_INIT,\x20identifies\
    \x20the\x20station\x20that\x20picked\x20up\n\n\r\n\x05\x04\x04\x02\x05\
    \x04\x12\x04\x93\x01\x04\x0c\n\r\n\x05\x04\x04\x02\x05\x05\x12\x04\x93\
    \x01\r\x13\n\r\n\x05\x04\x04\x02\x05\x01\x12\x04\x93\x01\x14\x1e\n\r\n\
    \x05\x04\x04\x02\x05\x03\x12\x04\x93\x01!\"\nG\n\x04\x04\x04\x02\x06\x12\
    \x04\x96\x01\x04!\x1a9\x20Random-sized\x20junk\x20to\x20defeat\x20packet\
    \x20size\x20fingerprinting.\n\n\r\n\x05\x04\x04\x02\x06\x04\x12\x04\x96\
    \x01\x04\x0c\n\r\n\x05\x04\x04\x02\x06\x05\x12\x04\x96\x01\r\x12\n\r\n\
    \x05\x04\x04\x02\x06\x01\x12\x04\x96\x01\x13\x1a\n\r\n\x05\x04\x04\x02\
    \x06\x03\x12\x04\x96\x01\x1d\x20\n\x0c\n\x02\x04\x05\x12\x06\x99\x01\0\
    \xbb\x01\x01\n\x0b\n\x03\x04\x05\x01\x12\x04\x99\x01\x08\x17\n\x0c\n\x04\
    \x04\x05\x02\0\x12\x04\x9a\x01\x04)\n\r\n\x05\x04\x05\x02\0\x04\x12\x04\
    \x9a\x01\x04\x0c\n\r\n\x05\x04\x05\x02\0\x05\x12\x04\x9a\x01\r\x13\n\r\n\
    \x05\x04\x05\x02\0\x01\x12\x04\x9a\x01\x14$\n\r\n\x05\x04\x05\x02\0\x03\
    \x12\x04\x9a\x01'(\n\xd0\x01\n\x04\x04\x05\x02\x01\x12\x04\x9f\x01\x04.\
    \x1a\xc1\x01\x20The\x20client\x20reports\x20its\x20decoy\x20list's\x20ve\
    rsion\x20number\x20here,\x20which\x20the\n\x20station\x20can\x20use\x20t\
    o\x20decide\x20whether\x20to\x20send\x20an\x20updated\x20one.\x20The\x20\
    station\n\x20should\x20always\x20send\x20a\x20list\x20if\x20this\x20fiel\
    d\x20is\x20set\x20to\x200.\n\n\r\n\x05\x04\x05\x02\x01\x04\x12\x04\x9f\
    \x01\x04\x0c\n\r\n\x05\x04\x05\x02\x01\x05\x12\x04\x9f\x01\r\x13\n\r\n\
    \x05\x04\x05\x02\x01\x01\x12\x04\x9f\x01\x14)\n\r\n\x05\x04\x05\x02\x01\
    \x03\x12\x04\x9f\x01,-\n\x0c\n\x04\x04\x05\x02\x02\x12\x04\xa1\x01\x041\
    \n\r\n\x05\x04\x05\x02\x02\x04\x12\x04\xa1\x01\x04\x0c\n\r\n\x05\x04\x05\
    \x02\x02\x06\x12\x04\xa1\x01\r\x1b\n\r\n\x05\x04\x05\x02\x02\x01\x12\x04\
    \xa1\x01\x1c,\n\r\n\x05\x04\x05\x02\x02\x03\x12\x04\xa1\x01/0\n\x80\x01\
    \n\x04\x04\x05\x02\x03\x12\x04\xa5\x01\x04$\x1ar\x20The\x20position\x20i\
    n\x20the\x20overall\x20session's\x20upload\x20sequence\x20where\x20the\
    \x20current\n\x20YIELD=>ACQUIRE\x20switchover\x20is\x20happening.\n\n\r\
    \n\x05\x04\x05\x02\x03\x04\x12\x04\xa5\x01\x04\x0c\n\r\n\x05\x04\x05\x02\
    \x03\x05\x12\x04\xa5\x01\r\x13\n\r\n\x05\x04\x05\x02\x03\x01\x12\x04\xa5\
    \x01\x14\x1f\n\r\n\x05\x04\x05\x02\x03\x03\x12\x04\xa5\x01\"#\nq\n\x04\
    \x04\x05\x02\x04\x12\x04\xaa\x01\x04'\x1ac\x20List\x20of\x20decoys\x20th\
    at\x20client\x20have\x20unsuccessfully\x20tried\x20in\x20current\x20sess\
    ion.\n\x20Could\x20be\x20sent\x20in\x20chunks\n\n\r\n\x05\x04\x05\x02\
    \x04\x04\x12\x04\xaa\x01\x04\x0c\n\r\n\x05\x04\x05\x02\x04\x05\x12\x04\
    \xaa\x01\r\x13\n\r\n\x05\x04\x05\x02\x04\x01\x12\x04\xaa\x01\x14!\n\r\n\
    \x05\x04\x05\x02\x04\x03\x12\x04\xaa\x01$&\n\x0c\n\x04\x04\x05\x02\x05\
    \x12\x04\xac\x01\x04%\n\r\n\x05\x04\x05\x02\x05\x04\x12\x04\xac\x01\x04\
    \x0c\n\r\n\x05\x04\x05\x02\x05\x06\x12\x04\xac\x01\r\x19\n\r\n\x05\x04\
    \x05\x02\x05\x01\x12\x04\xac\x01\x1a\x1f\n\r\n\x05\x04\x05\x02\x05\x03\
    \x12\x04\xac\x01\"$\n\xc8\x03\n\x04\x04\x05\x02\x06\x12\x04\xb4\x01\x04(\
    \x1a\xb9\x03\x20Station\x20is\x20only\x20required\x20to\x20check\x20this\
    \x20variable\x20during\x20session\x20initialization.\n\x20If\x20set,\x20\
    station\x20must\x20facilitate\x20connection\x20to\x20said\x20target\x20b\
    y\x20itself,\x20i.e.\x20write\x20into\x20squid\n\x20socket\x20an\x20HTTP\
    /SOCKS/any\x20other\x20connection\x20request.\n\x20covert_address\x20mus\
    t\x20have\x20exactly\x20one\x20':'\x20colon,\x20that\x20separates\x20hos\
    t\x20(literal\x20IP\x20address\x20or\n\x20resolvable\x20hostname)\x20and\
    \x20port\n\x20TODO:\x20make\x20it\x20required\x20for\x20initialization,\
    \x20and\x20stop\x20connecting\x20any\x20client\x20straight\x20to\x20squi\
    d?\n\n\r\n\x05\x04\x05\x02\x06\x04\x12\x04\xb4\x01\x04\x0c\n\r\n\x05\x04\
    \x05\x02\x06\x05\x12\x04\xb4\x01\r\x13\n\r\n\x05\x04\x05\x02\x06\x01\x12\
    \x04\xb4\x01\x14\"\n\r\n\x05\x04\x05\x02\x06\x03\x12\x04\xb4\x01%'\nR\n\
    \x04\x04\x05\x02\x07\x12\x04\xb7\x01\x042\x1aD\x20Used\x20in\x20dark\x20\
    decoys\x20to\x20signal\x20which\x20dark\x20decoy\x20it\x20will\x20connec\
    t\x20to.\n\n\r\n\x05\x04\x05\x02\x07\x04\x12\x04\xb7\x01\x04\x0c\n\r\n\
    \x05\x04\x05\x02\x07\x05\x12\x04\xb7\x01\r\x13\n\r\n\x05\x04\x05\x02\x07\
    \x01\x12\x04\xb7\x01\x14,\n\r\n\x05\x04\x05\x02\x07\x03\x12\x04\xb7\x01/\
    1\nG\n\x04\x04\x05\x02\x08\x12\x04\xba\x01\x04!\x1a9\x20Random-sized\x20\
    junk\x20to\x20defeat\x20packet\x20size\x20fingerprinting.\n\n\r\n\x05\
    \x04\x05\x02\x08\x04\x12\x04\xba\x01\x04\x0c\n\r\n\x05\x04\x05\x02\x08\
    \x05\x12\x04\xba\x01\r\x12\n\r\n\x05\x04\x05\x02\x08\x01\x12\x04\xba\x01\
    \x13\x1a\n\r\n\x05\x04\x05\x02\x08\x03\x12\x04\xba\x01\x1d\x20\n\x0c\n\
    \x02\x04\x06\x12\x06\xbd\x01\0\xc9\x01\x01\n\x0b\n\x03\x04\x06\x01\x12\
    \x04\xbd\x01\x08\x14\n9\n\x04\x04\x06\x02\0\x12\x04\xbe\x01\x04.\"+\x20h\
    ow\x20many\x20decoys\x20were\x20tried\x20before\x20success\n\n\r\n\x05\
    \x04\x06\x02\0\x04\x12\x04\xbe\x01\x04\x0c\n\r\n\x05\x04\x06\x02\0\x05\
    \x12\x04\xbe\x01\r\x13\n\r\n\x05\x04\x06\x02\0\x01\x12\x04\xbe\x01\x14(\
    \n\r\n\x05\x04\x06\x02\0\x03\x12\x04\xbe\x01+-\nH\n\x04\x04\x06\x02\x01\
    \x12\x04\xc3\x01\x04/\x1a\x1e\x20Applicable\x20to\x20whole\x20session:\n\
    \"\x1a\x20includes\x20failed\x20attempts\n\n\r\n\x05\x04\x06\x02\x01\x04\
    \x12\x04\xc3\x01\x04\x0c\n\r\n\x05\x04\x06\x02\x01\x05\x12\x04\xc3\x01\r\
    \x13\n\r\n\x05\x04\x06\x02\x01\x01\x12\x04\xc3\x01\x14)\n\r\n\x05\x04\
    \x06\x02\x01\x03\x12\x04\xc3\x01,.\nR\n\x04\x04\x06\x02\x02\x12\x04\xc6\
    \x01\x04(\x1a\x1f\x20Last\x20(i.e.\x20successful)\x20decoy:\n\"#\x20meas\
    ured\x20during\x20initial\x20handshake\n\n\r\n\x05\x04\x06\x02\x02\x04\
    \x12\x04\xc6\x01\x04\x0c\n\r\n\x05\x04\x06\x02\x02\x05\x12\x04\xc6\x01\r\
    \x13\n\r\n\x05\x04\x06\x02\x02\x01\x12\x04\xc6\x01\x14\"\n\r\n\x05\x04\
    \x06\x02\x02\x03\x12\x04\xc6\x01%'\n%\n\x04\x04\x06\x02\x03\x12\x04\xc7\
    \x01\x04&\"\x17\x20includes\x20tcp\x20to\x20decoy\n\n\r\n\x05\x04\x06\
    \x02\x03\x04\x12\x04\xc7\x01\x04\x0c\n\r\n\x05\x04\x06\x02\x03\x05\x12\
    \x04\xc7\x01\r\x13\n\r\n\x05\x04\x06\x02\x03\x01\x12\x04\xc7\x01\x14\x20\
    \n\r\n\x05\x04\x06\x02\x03\x03\x12\x04\xc7\x01#%\nB\n\x04\x04\x06\x02\
    \x04\x12\x04\xc8\x01\x04&\"4\x20measured\x20when\x20establishing\x20tcp\
    \x20connection\x20to\x20decot\n\n\r\n\x05\x04\x06\x02\x04\x04\x12\x04\
    \xc8\x01\x04\x0c\n\r\n\x05\x04\x06\x02\x04\x05\x12\x04\xc8\x01\r\x13\n\r\
    \n\x05\x04\x06\x02\x04\x01\x12\x04\xc8\x01\x14\x20\n\r\n\x05\x04\x06\x02\
    \x04\x03\x12\x04\xc8\x01#%\
";

static mut file_descriptor_proto_lazy: ::protobuf::lazy::Lazy<::protobuf::descriptor::FileDescriptorProto> = ::protobuf::lazy::Lazy {
    lock: ::protobuf::lazy::ONCE_INIT,
    ptr: 0 as *const ::protobuf::descriptor::FileDescriptorProto,
};

fn parse_descriptor_proto() -> ::protobuf::descriptor::FileDescriptorProto {
    ::protobuf::parse_from_bytes(file_descriptor_proto_data).unwrap()
}

pub fn file_descriptor_proto() -> &'static ::protobuf::descriptor::FileDescriptorProto {
    unsafe {
        file_descriptor_proto_lazy.get(|| {
            parse_descriptor_proto()
        })
    }
}
