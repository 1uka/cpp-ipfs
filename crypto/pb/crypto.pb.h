// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: crypto.proto

#ifndef PROTOBUF_crypto_2eproto__INCLUDED
#define PROTOBUF_crypto_2eproto__INCLUDED

#include <string>

#include <google/protobuf/stubs/common.h>

#if GOOGLE_PROTOBUF_VERSION < 3005000
#error This file was generated by a newer version of protoc which is
#error incompatible with your Protocol Buffer headers.  Please update
#error your headers.
#endif
#if 3005001 < GOOGLE_PROTOBUF_MIN_PROTOC_VERSION
#error This file was generated by an older version of protoc which is
#error incompatible with your Protocol Buffer headers.  Please
#error regenerate this file with a newer version of protoc.
#endif

#include <google/protobuf/io/coded_stream.h>
#include <google/protobuf/arena.h>
#include <google/protobuf/arenastring.h>
#include <google/protobuf/generated_message_table_driven.h>
#include <google/protobuf/generated_message_util.h>
#include <google/protobuf/metadata.h>
#include <google/protobuf/message.h>
#include <google/protobuf/repeated_field.h>  // IWYU pragma: export
#include <google/protobuf/extension_set.h>  // IWYU pragma: export
#include <google/protobuf/generated_enum_reflection.h>
#include <google/protobuf/unknown_field_set.h>
// @@protoc_insertion_point(includes)

namespace protobuf_crypto_2eproto {
// Internal implementation detail -- do not use these members.
struct TableStruct {
  static const ::google::protobuf::internal::ParseTableField entries[];
  static const ::google::protobuf::internal::AuxillaryParseTableField aux[];
  static const ::google::protobuf::internal::ParseTable schema[2];
  static const ::google::protobuf::internal::FieldMetadata field_metadata[];
  static const ::google::protobuf::internal::SerializationTable serialization_table[];
  static const ::google::protobuf::uint32 offsets[];
};
void AddDescriptors();
void InitDefaultsPublicKeyImpl();
void InitDefaultsPublicKey();
void InitDefaultsPrivateKeyImpl();
void InitDefaultsPrivateKey();
inline void InitDefaults() {
  InitDefaultsPublicKey();
  InitDefaultsPrivateKey();
}
}  // namespace protobuf_crypto_2eproto
namespace crypto {
namespace pb {
class PrivateKey;
class PrivateKeyDefaultTypeInternal;
extern PrivateKeyDefaultTypeInternal _PrivateKey_default_instance_;
class PublicKey;
class PublicKeyDefaultTypeInternal;
extern PublicKeyDefaultTypeInternal _PublicKey_default_instance_;
}  // namespace pb
}  // namespace crypto
namespace crypto {
namespace pb {

enum KeyType {
  RSA = 0,
  Ed25519 = 1,
  Secp256k1 = 2
};
bool KeyType_IsValid(int value);
const KeyType KeyType_MIN = RSA;
const KeyType KeyType_MAX = Secp256k1;
const int KeyType_ARRAYSIZE = KeyType_MAX + 1;

const ::google::protobuf::EnumDescriptor* KeyType_descriptor();
inline const ::std::string& KeyType_Name(KeyType value) {
  return ::google::protobuf::internal::NameOfEnum(
    KeyType_descriptor(), value);
}
inline bool KeyType_Parse(
    const ::std::string& name, KeyType* value) {
  return ::google::protobuf::internal::ParseNamedEnum<KeyType>(
    KeyType_descriptor(), name, value);
}
// ===================================================================

class PublicKey : public ::google::protobuf::Message /* @@protoc_insertion_point(class_definition:crypto.pb.PublicKey) */ {
 public:
  PublicKey();
  virtual ~PublicKey();

  PublicKey(const PublicKey& from);

  inline PublicKey& operator=(const PublicKey& from) {
    CopyFrom(from);
    return *this;
  }
  #if LANG_CXX11
  PublicKey(PublicKey&& from) noexcept
    : PublicKey() {
    *this = ::std::move(from);
  }

  inline PublicKey& operator=(PublicKey&& from) noexcept {
    if (GetArenaNoVirtual() == from.GetArenaNoVirtual()) {
      if (this != &from) InternalSwap(&from);
    } else {
      CopyFrom(from);
    }
    return *this;
  }
  #endif
  inline const ::google::protobuf::UnknownFieldSet& unknown_fields() const {
    return _internal_metadata_.unknown_fields();
  }
  inline ::google::protobuf::UnknownFieldSet* mutable_unknown_fields() {
    return _internal_metadata_.mutable_unknown_fields();
  }

  static const ::google::protobuf::Descriptor* descriptor();
  static const PublicKey& default_instance();

  static void InitAsDefaultInstance();  // FOR INTERNAL USE ONLY
  static inline const PublicKey* internal_default_instance() {
    return reinterpret_cast<const PublicKey*>(
               &_PublicKey_default_instance_);
  }
  static PROTOBUF_CONSTEXPR int const kIndexInFileMessages =
    0;

  void Swap(PublicKey* other);
  friend void swap(PublicKey& a, PublicKey& b) {
    a.Swap(&b);
  }

  // implements Message ----------------------------------------------

  inline PublicKey* New() const PROTOBUF_FINAL { return New(NULL); }

  PublicKey* New(::google::protobuf::Arena* arena) const PROTOBUF_FINAL;
  void CopyFrom(const ::google::protobuf::Message& from) PROTOBUF_FINAL;
  void MergeFrom(const ::google::protobuf::Message& from) PROTOBUF_FINAL;
  void CopyFrom(const PublicKey& from);
  void MergeFrom(const PublicKey& from);
  void Clear() PROTOBUF_FINAL;
  bool IsInitialized() const PROTOBUF_FINAL;

  size_t ByteSizeLong() const PROTOBUF_FINAL;
  bool MergePartialFromCodedStream(
      ::google::protobuf::io::CodedInputStream* input) PROTOBUF_FINAL;
  void SerializeWithCachedSizes(
      ::google::protobuf::io::CodedOutputStream* output) const PROTOBUF_FINAL;
  ::google::protobuf::uint8* InternalSerializeWithCachedSizesToArray(
      bool deterministic, ::google::protobuf::uint8* target) const PROTOBUF_FINAL;
  int GetCachedSize() const PROTOBUF_FINAL { return _cached_size_; }
  private:
  void SharedCtor();
  void SharedDtor();
  void SetCachedSize(int size) const PROTOBUF_FINAL;
  void InternalSwap(PublicKey* other);
  private:
  inline ::google::protobuf::Arena* GetArenaNoVirtual() const {
    return NULL;
  }
  inline void* MaybeArenaPtr() const {
    return NULL;
  }
  public:

  ::google::protobuf::Metadata GetMetadata() const PROTOBUF_FINAL;

  // nested types ----------------------------------------------------

  // accessors -------------------------------------------------------

  // required bytes Data = 2;
  bool has_data() const;
  void clear_data();
  static const int kDataFieldNumber = 2;
  const ::std::string& data() const;
  void set_data(const ::std::string& value);
  #if LANG_CXX11
  void set_data(::std::string&& value);
  #endif
  void set_data(const char* value);
  void set_data(const void* value, size_t size);
  ::std::string* mutable_data();
  ::std::string* release_data();
  void set_allocated_data(::std::string* data);

  // required .crypto.pb.KeyType Type = 1;
  bool has_type() const;
  void clear_type();
  static const int kTypeFieldNumber = 1;
  ::crypto::pb::KeyType type() const;
  void set_type(::crypto::pb::KeyType value);

  // @@protoc_insertion_point(class_scope:crypto.pb.PublicKey)
 private:
  void set_has_type();
  void clear_has_type();
  void set_has_data();
  void clear_has_data();

  // helper for ByteSizeLong()
  size_t RequiredFieldsByteSizeFallback() const;

  ::google::protobuf::internal::InternalMetadataWithArena _internal_metadata_;
  ::google::protobuf::internal::HasBits<1> _has_bits_;
  mutable int _cached_size_;
  ::google::protobuf::internal::ArenaStringPtr data_;
  int type_;
  friend struct ::protobuf_crypto_2eproto::TableStruct;
  friend void ::protobuf_crypto_2eproto::InitDefaultsPublicKeyImpl();
};
// -------------------------------------------------------------------

class PrivateKey : public ::google::protobuf::Message /* @@protoc_insertion_point(class_definition:crypto.pb.PrivateKey) */ {
 public:
  PrivateKey();
  virtual ~PrivateKey();

  PrivateKey(const PrivateKey& from);

  inline PrivateKey& operator=(const PrivateKey& from) {
    CopyFrom(from);
    return *this;
  }
  #if LANG_CXX11
  PrivateKey(PrivateKey&& from) noexcept
    : PrivateKey() {
    *this = ::std::move(from);
  }

  inline PrivateKey& operator=(PrivateKey&& from) noexcept {
    if (GetArenaNoVirtual() == from.GetArenaNoVirtual()) {
      if (this != &from) InternalSwap(&from);
    } else {
      CopyFrom(from);
    }
    return *this;
  }
  #endif
  inline const ::google::protobuf::UnknownFieldSet& unknown_fields() const {
    return _internal_metadata_.unknown_fields();
  }
  inline ::google::protobuf::UnknownFieldSet* mutable_unknown_fields() {
    return _internal_metadata_.mutable_unknown_fields();
  }

  static const ::google::protobuf::Descriptor* descriptor();
  static const PrivateKey& default_instance();

  static void InitAsDefaultInstance();  // FOR INTERNAL USE ONLY
  static inline const PrivateKey* internal_default_instance() {
    return reinterpret_cast<const PrivateKey*>(
               &_PrivateKey_default_instance_);
  }
  static PROTOBUF_CONSTEXPR int const kIndexInFileMessages =
    1;

  void Swap(PrivateKey* other);
  friend void swap(PrivateKey& a, PrivateKey& b) {
    a.Swap(&b);
  }

  // implements Message ----------------------------------------------

  inline PrivateKey* New() const PROTOBUF_FINAL { return New(NULL); }

  PrivateKey* New(::google::protobuf::Arena* arena) const PROTOBUF_FINAL;
  void CopyFrom(const ::google::protobuf::Message& from) PROTOBUF_FINAL;
  void MergeFrom(const ::google::protobuf::Message& from) PROTOBUF_FINAL;
  void CopyFrom(const PrivateKey& from);
  void MergeFrom(const PrivateKey& from);
  void Clear() PROTOBUF_FINAL;
  bool IsInitialized() const PROTOBUF_FINAL;

  size_t ByteSizeLong() const PROTOBUF_FINAL;
  bool MergePartialFromCodedStream(
      ::google::protobuf::io::CodedInputStream* input) PROTOBUF_FINAL;
  void SerializeWithCachedSizes(
      ::google::protobuf::io::CodedOutputStream* output) const PROTOBUF_FINAL;
  ::google::protobuf::uint8* InternalSerializeWithCachedSizesToArray(
      bool deterministic, ::google::protobuf::uint8* target) const PROTOBUF_FINAL;
  int GetCachedSize() const PROTOBUF_FINAL { return _cached_size_; }
  private:
  void SharedCtor();
  void SharedDtor();
  void SetCachedSize(int size) const PROTOBUF_FINAL;
  void InternalSwap(PrivateKey* other);
  private:
  inline ::google::protobuf::Arena* GetArenaNoVirtual() const {
    return NULL;
  }
  inline void* MaybeArenaPtr() const {
    return NULL;
  }
  public:

  ::google::protobuf::Metadata GetMetadata() const PROTOBUF_FINAL;

  // nested types ----------------------------------------------------

  // accessors -------------------------------------------------------

  // required bytes Data = 2;
  bool has_data() const;
  void clear_data();
  static const int kDataFieldNumber = 2;
  const ::std::string& data() const;
  void set_data(const ::std::string& value);
  #if LANG_CXX11
  void set_data(::std::string&& value);
  #endif
  void set_data(const char* value);
  void set_data(const void* value, size_t size);
  ::std::string* mutable_data();
  ::std::string* release_data();
  void set_allocated_data(::std::string* data);

  // required .crypto.pb.KeyType Type = 1;
  bool has_type() const;
  void clear_type();
  static const int kTypeFieldNumber = 1;
  ::crypto::pb::KeyType type() const;
  void set_type(::crypto::pb::KeyType value);

  // @@protoc_insertion_point(class_scope:crypto.pb.PrivateKey)
 private:
  void set_has_type();
  void clear_has_type();
  void set_has_data();
  void clear_has_data();

  // helper for ByteSizeLong()
  size_t RequiredFieldsByteSizeFallback() const;

  ::google::protobuf::internal::InternalMetadataWithArena _internal_metadata_;
  ::google::protobuf::internal::HasBits<1> _has_bits_;
  mutable int _cached_size_;
  ::google::protobuf::internal::ArenaStringPtr data_;
  int type_;
  friend struct ::protobuf_crypto_2eproto::TableStruct;
  friend void ::protobuf_crypto_2eproto::InitDefaultsPrivateKeyImpl();
};
// ===================================================================


// ===================================================================

#ifdef __GNUC__
  #pragma GCC diagnostic push
  #pragma GCC diagnostic ignored "-Wstrict-aliasing"
#endif  // __GNUC__
// PublicKey

// required .crypto.pb.KeyType Type = 1;
inline bool PublicKey::has_type() const {
  return (_has_bits_[0] & 0x00000002u) != 0;
}
inline void PublicKey::set_has_type() {
  _has_bits_[0] |= 0x00000002u;
}
inline void PublicKey::clear_has_type() {
  _has_bits_[0] &= ~0x00000002u;
}
inline void PublicKey::clear_type() {
  type_ = 0;
  clear_has_type();
}
inline ::crypto::pb::KeyType PublicKey::type() const {
  // @@protoc_insertion_point(field_get:crypto.pb.PublicKey.Type)
  return static_cast< ::crypto::pb::KeyType >(type_);
}
inline void PublicKey::set_type(::crypto::pb::KeyType value) {
  assert(::crypto::pb::KeyType_IsValid(value));
  set_has_type();
  type_ = value;
  // @@protoc_insertion_point(field_set:crypto.pb.PublicKey.Type)
}

// required bytes Data = 2;
inline bool PublicKey::has_data() const {
  return (_has_bits_[0] & 0x00000001u) != 0;
}
inline void PublicKey::set_has_data() {
  _has_bits_[0] |= 0x00000001u;
}
inline void PublicKey::clear_has_data() {
  _has_bits_[0] &= ~0x00000001u;
}
inline void PublicKey::clear_data() {
  data_.ClearToEmptyNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
  clear_has_data();
}
inline const ::std::string& PublicKey::data() const {
  // @@protoc_insertion_point(field_get:crypto.pb.PublicKey.Data)
  return data_.GetNoArena();
}
inline void PublicKey::set_data(const ::std::string& value) {
  set_has_data();
  data_.SetNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited(), value);
  // @@protoc_insertion_point(field_set:crypto.pb.PublicKey.Data)
}
#if LANG_CXX11
inline void PublicKey::set_data(::std::string&& value) {
  set_has_data();
  data_.SetNoArena(
    &::google::protobuf::internal::GetEmptyStringAlreadyInited(), ::std::move(value));
  // @@protoc_insertion_point(field_set_rvalue:crypto.pb.PublicKey.Data)
}
#endif
inline void PublicKey::set_data(const char* value) {
  GOOGLE_DCHECK(value != NULL);
  set_has_data();
  data_.SetNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited(), ::std::string(value));
  // @@protoc_insertion_point(field_set_char:crypto.pb.PublicKey.Data)
}
inline void PublicKey::set_data(const void* value, size_t size) {
  set_has_data();
  data_.SetNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited(),
      ::std::string(reinterpret_cast<const char*>(value), size));
  // @@protoc_insertion_point(field_set_pointer:crypto.pb.PublicKey.Data)
}
inline ::std::string* PublicKey::mutable_data() {
  set_has_data();
  // @@protoc_insertion_point(field_mutable:crypto.pb.PublicKey.Data)
  return data_.MutableNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
}
inline ::std::string* PublicKey::release_data() {
  // @@protoc_insertion_point(field_release:crypto.pb.PublicKey.Data)
  clear_has_data();
  return data_.ReleaseNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
}
inline void PublicKey::set_allocated_data(::std::string* data) {
  if (data != NULL) {
    set_has_data();
  } else {
    clear_has_data();
  }
  data_.SetAllocatedNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited(), data);
  // @@protoc_insertion_point(field_set_allocated:crypto.pb.PublicKey.Data)
}

// -------------------------------------------------------------------

// PrivateKey

// required .crypto.pb.KeyType Type = 1;
inline bool PrivateKey::has_type() const {
  return (_has_bits_[0] & 0x00000002u) != 0;
}
inline void PrivateKey::set_has_type() {
  _has_bits_[0] |= 0x00000002u;
}
inline void PrivateKey::clear_has_type() {
  _has_bits_[0] &= ~0x00000002u;
}
inline void PrivateKey::clear_type() {
  type_ = 0;
  clear_has_type();
}
inline ::crypto::pb::KeyType PrivateKey::type() const {
  // @@protoc_insertion_point(field_get:crypto.pb.PrivateKey.Type)
  return static_cast< ::crypto::pb::KeyType >(type_);
}
inline void PrivateKey::set_type(::crypto::pb::KeyType value) {
  assert(::crypto::pb::KeyType_IsValid(value));
  set_has_type();
  type_ = value;
  // @@protoc_insertion_point(field_set:crypto.pb.PrivateKey.Type)
}

// required bytes Data = 2;
inline bool PrivateKey::has_data() const {
  return (_has_bits_[0] & 0x00000001u) != 0;
}
inline void PrivateKey::set_has_data() {
  _has_bits_[0] |= 0x00000001u;
}
inline void PrivateKey::clear_has_data() {
  _has_bits_[0] &= ~0x00000001u;
}
inline void PrivateKey::clear_data() {
  data_.ClearToEmptyNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
  clear_has_data();
}
inline const ::std::string& PrivateKey::data() const {
  // @@protoc_insertion_point(field_get:crypto.pb.PrivateKey.Data)
  return data_.GetNoArena();
}
inline void PrivateKey::set_data(const ::std::string& value) {
  set_has_data();
  data_.SetNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited(), value);
  // @@protoc_insertion_point(field_set:crypto.pb.PrivateKey.Data)
}
#if LANG_CXX11
inline void PrivateKey::set_data(::std::string&& value) {
  set_has_data();
  data_.SetNoArena(
    &::google::protobuf::internal::GetEmptyStringAlreadyInited(), ::std::move(value));
  // @@protoc_insertion_point(field_set_rvalue:crypto.pb.PrivateKey.Data)
}
#endif
inline void PrivateKey::set_data(const char* value) {
  GOOGLE_DCHECK(value != NULL);
  set_has_data();
  data_.SetNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited(), ::std::string(value));
  // @@protoc_insertion_point(field_set_char:crypto.pb.PrivateKey.Data)
}
inline void PrivateKey::set_data(const void* value, size_t size) {
  set_has_data();
  data_.SetNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited(),
      ::std::string(reinterpret_cast<const char*>(value), size));
  // @@protoc_insertion_point(field_set_pointer:crypto.pb.PrivateKey.Data)
}
inline ::std::string* PrivateKey::mutable_data() {
  set_has_data();
  // @@protoc_insertion_point(field_mutable:crypto.pb.PrivateKey.Data)
  return data_.MutableNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
}
inline ::std::string* PrivateKey::release_data() {
  // @@protoc_insertion_point(field_release:crypto.pb.PrivateKey.Data)
  clear_has_data();
  return data_.ReleaseNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
}
inline void PrivateKey::set_allocated_data(::std::string* data) {
  if (data != NULL) {
    set_has_data();
  } else {
    clear_has_data();
  }
  data_.SetAllocatedNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited(), data);
  // @@protoc_insertion_point(field_set_allocated:crypto.pb.PrivateKey.Data)
}

#ifdef __GNUC__
  #pragma GCC diagnostic pop
#endif  // __GNUC__
// -------------------------------------------------------------------


// @@protoc_insertion_point(namespace_scope)

}  // namespace pb
}  // namespace crypto

namespace google {
namespace protobuf {

template <> struct is_proto_enum< ::crypto::pb::KeyType> : ::google::protobuf::internal::true_type {};
template <>
inline const EnumDescriptor* GetEnumDescriptor< ::crypto::pb::KeyType>() {
  return ::crypto::pb::KeyType_descriptor();
}

}  // namespace protobuf
}  // namespace google

// @@protoc_insertion_point(global_scope)

#endif  // PROTOBUF_crypto_2eproto__INCLUDED