use libc;

#[link(name="seccomp_internal", kind="static")]
extern "C" {
    pub static C_ARCH_NATIVE: libc::uint32_t;
    pub static C_ARCH_X86: libc::uint32_t;
    pub static C_ARCH_X86_64: libc::uint32_t;
    pub static C_ARCH_X32: libc::uint32_t;
    pub static C_ARCH_ARM: libc::uint32_t;
    pub static C_ARCH_AARCH64: libc::uint32_t;
    pub static C_ARCH_MIPS: libc::uint32_t;
    pub static C_ARCH_MIPS64: libc::uint32_t;
    pub static C_ARCH_MIPS64N32: libc::uint32_t;
    pub static C_ARCH_MIPSEL: libc::uint32_t;
    pub static C_ARCH_MIPSEL64: libc::uint32_t;
    pub static C_ARCH_MIPSEL64N32: libc::uint32_t;

    pub static C_ACT_KILL: libc::uint32_t;
    pub static C_ACT_TRAP: libc::uint32_t;
    pub static C_ACT_ERRNO: libc::uint32_t;
    pub static C_ACT_TRACE: libc::uint32_t;
    pub static C_ACT_ALLOW: libc::uint32_t;

    pub static C_ATTRIBUTE_DEFAULT: libc::uint32_t;
    pub static C_ATTRIBUTE_BADARCH: libc::uint32_t;
    pub static C_ATTRIBUTE_NNP: libc::uint32_t;
    pub static C_ATTRIBUTE_TSYNC: libc::uint32_t;

    pub static C_CMP_NE: libc::c_int;
    pub static C_CMP_LT: libc::c_int;
    pub static C_CMP_LE: libc::c_int;
    pub static C_CMP_EQ: libc::c_int;
    pub static C_CMP_GE: libc::c_int;
    pub static C_CMP_GT: libc::c_int;
    pub static C_CMP_MASKED_EQ: libc::c_int;

    pub static C_VERSION_MAJOR: libc::c_int;
    pub static C_VERSION_MINOR: libc::c_int;
    pub static C_VERSION_MICRO: libc::c_int;
}

pub enum scmpFilterAttr {
    filterAttrActDefault,
    filterAttrActBadArch,
    filterAttrNNP,
    filterAttrTsync,
}

/*
verMajor: i32 = C_VERSION_MAJOR;
verMinor: i32 = C_VERSION_MINOR;
verMicro: i32 = C_VERSION_MICRO;
*/

fn checkVersionAbove(major: i32, minor: i32, micro: i32) -> bool {
    (C_VERSION_MAJOR > major) || (C_VERSION_MAJOR == major && C_VERSION_MINOR > minor) ||
    (C_VERSION_MAJOR == major && C_VERSION_MINOR == minor && C_VERSION_MICRO > micro)
}
