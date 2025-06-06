#ifndef __BPF_TYPES_FIX_H__
#define __BPF_TYPES_FIX_H__

#include <linux/types.h>
/* Here We Just are ensuring basic types are defined */
#ifndef __u8
#define __u8 unsigned char
#endif

#ifndef __u16
#define __u16 unsigned short
#endif

#ifndef __u64
#define __u64 unsigned long long
#endif

#ifndef __s8
#define __s8 signed char
#endif

#ifndef __s16
#define __s16 signed short
#endif

#ifndef __s32
#define __s32 signed int
#endif

#ifndef __s64
#define __s64 signed long long
#endif

#endif /* __BPF_TYPES_FIX_H__ */
