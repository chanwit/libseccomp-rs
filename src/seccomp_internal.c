#include <stdlib.h>
#include <seccomp.h>

#if SCMP_VER_MAJOR < 2
#error Minimum supported version of Libseccomp is v2.1.0
#elif SCMP_VER_MAJOR == 2 && SCMP_VER_MINOR < 1
#error Minimum supported version of Libseccomp is v2.1.0
#endif

#define ARCH_BAD ~0

const uint32_t C_ARCH_BAD = ARCH_BAD;

#ifndef SCMP_ARCH_AARCH64
#define SCMP_ARCH_AARCH64 ARCH_BAD
#endif

#ifndef SCMP_ARCH_MIPS
#define SCMP_ARCH_MIPS ARCH_BAD
#endif

#ifndef SCMP_ARCH_MIPS64
#define SCMP_ARCH_MIPS64 ARCH_BAD
#endif

#ifndef SCMP_ARCH_MIPS64N32
#define SCMP_ARCH_MIPS64N32 ARCH_BAD
#endif

#ifndef SCMP_ARCH_MIPSEL
#define SCMP_ARCH_MIPSEL ARCH_BAD
#endif

#ifndef SCMP_ARCH_MIPSEL64
#define SCMP_ARCH_MIPSEL64 ARCH_BAD
#endif

#ifndef SCMP_ARCH_MIPSEL64N32
#define SCMP_ARCH_MIPSEL64N32 ARCH_BAD
#endif

const uint32_t C_ARCH_NATIVE       = SCMP_ARCH_NATIVE;
const uint32_t C_ARCH_X86          = SCMP_ARCH_X86;
const uint32_t C_ARCH_X86_64       = SCMP_ARCH_X86_64;
const uint32_t C_ARCH_X32          = SCMP_ARCH_X32;
const uint32_t C_ARCH_ARM          = SCMP_ARCH_ARM;
const uint32_t C_ARCH_AARCH64      = SCMP_ARCH_AARCH64;
const uint32_t C_ARCH_MIPS         = SCMP_ARCH_MIPS;
const uint32_t C_ARCH_MIPS64       = SCMP_ARCH_MIPS64;
const uint32_t C_ARCH_MIPS64N32    = SCMP_ARCH_MIPS64N32;
const uint32_t C_ARCH_MIPSEL       = SCMP_ARCH_MIPSEL;
const uint32_t C_ARCH_MIPSEL64     = SCMP_ARCH_MIPSEL64;
const uint32_t C_ARCH_MIPSEL64N32  = SCMP_ARCH_MIPSEL64N32;

const uint32_t C_ACT_KILL          = SCMP_ACT_KILL;
const uint32_t C_ACT_TRAP          = SCMP_ACT_TRAP;
const uint32_t C_ACT_ERRNO         = SCMP_ACT_ERRNO(0);
const uint32_t C_ACT_TRACE         = SCMP_ACT_TRACE(0);
const uint32_t C_ACT_ALLOW         = SCMP_ACT_ALLOW;

// If TSync is not supported, make sure it doesn't map to a supported filter attribute
// Don't worry about major version < 2, the minimum version checks should catch that case
#if SCMP_VER_MAJOR == 2 && SCMP_VER_MINOR < 2
#define SCMP_FLTATR_CTL_TSYNC _SCMP_CMP_MIN
#endif

const uint32_t C_ATTRIBUTE_DEFAULT = (uint32_t)SCMP_FLTATR_ACT_DEFAULT;
const uint32_t C_ATTRIBUTE_BADARCH = (uint32_t)SCMP_FLTATR_ACT_BADARCH;
const uint32_t C_ATTRIBUTE_NNP     = (uint32_t)SCMP_FLTATR_CTL_NNP;
const uint32_t C_ATTRIBUTE_TSYNC   = (uint32_t)SCMP_FLTATR_CTL_TSYNC;

const int      C_CMP_NE            = (int)SCMP_CMP_NE;
const int      C_CMP_LT            = (int)SCMP_CMP_LT;
const int      C_CMP_LE            = (int)SCMP_CMP_LE;
const int      C_CMP_EQ            = (int)SCMP_CMP_EQ;
const int      C_CMP_GE            = (int)SCMP_CMP_GE;
const int      C_CMP_GT            = (int)SCMP_CMP_GT;
const int      C_CMP_MASKED_EQ     = (int)SCMP_CMP_MASKED_EQ;

const int      C_VERSION_MAJOR     = SCMP_VER_MAJOR;
const int      C_VERSION_MINOR     = SCMP_VER_MINOR;
const int      C_VERSION_MICRO     = SCMP_VER_MICRO;

typedef struct scmp_arg_cmp* scmp_cast_t;

// Wrapper to create an scmp_arg_cmp struct
void*
make_struct_arg_cmp(
                    unsigned int arg,
                    int compare,
                    uint64_t a,
                    uint64_t b
                   )
{
	struct scmp_arg_cmp *s = malloc(sizeof(struct scmp_arg_cmp));

	s->arg = arg;
	s->op = compare;
	s->datum_a = a;
	s->datum_b = b;

	return s;
}
