/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: p1.proto */

#ifndef PROTOBUF_C_p1_2eproto__INCLUDED
#define PROTOBUF_C_p1_2eproto__INCLUDED

#include <protobuf-c/protobuf-c.h>

PROTOBUF_C__BEGIN_DECLS

#if PROTOBUF_C_VERSION_NUMBER < 1003000
# error This file was generated by a newer version of protoc-c which is incompatible with your libprotobuf-c headers. Please update your headers.
#elif 1003000 < PROTOBUF_C_MIN_COMPILER_VERSION
# error This file was generated by an older version of protoc-c which is incompatible with your libprotobuf-c headers. Please regenerate this file with a newer version of protoc-c.
#endif


typedef struct _Trans__One Trans__One;


/* --- enums --- */


/* --- messages --- */

struct  _Trans__One
{
  ProtobufCMessage base;
  int32_t a;
  int32_t b;
  char *c;
};
#define TRANS__ONE__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&trans__one__descriptor) \
    , 0, 0, (char *)protobuf_c_empty_string }


/* Trans__One methods */
void   trans__one__init
                     (Trans__One         *message);
size_t trans__one__get_packed_size
                     (const Trans__One   *message);
size_t trans__one__pack
                     (const Trans__One   *message,
                      uint8_t             *out);
size_t trans__one__pack_to_buffer
                     (const Trans__One   *message,
                      ProtobufCBuffer     *buffer);
Trans__One *
       trans__one__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   trans__one__free_unpacked
                     (Trans__One *message,
                      ProtobufCAllocator *allocator);
/* --- per-message closures --- */

typedef void (*Trans__One_Closure)
                 (const Trans__One *message,
                  void *closure_data);

/* --- services --- */


/* --- descriptors --- */

extern const ProtobufCMessageDescriptor trans__one__descriptor;

PROTOBUF_C__END_DECLS


#endif  /* PROTOBUF_C_p1_2eproto__INCLUDED */
