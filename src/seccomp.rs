use libc;
use std::ffi::CStr;
use std::ptr;

extern "C" {
    pub static C_ARCH_BAD: libc::uint32_t;

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

    fn seccomp_syscall_resolve_num_arch(arch: libc::uint32_t,
                                        syscall: libc::c_int)
                                        -> *const libc::c_char;
}

pub enum ScmpFilterAttr {
    FilterAttrActDefault,
    FilterAttrActBadArch,
    FilterAttrNNP,
    FilterAttrTsync,
}

pub fn check_version_above(major: i32, minor: i32, micro: i32) -> bool {
    (C_VERSION_MAJOR > major) || (C_VERSION_MAJOR == major && C_VERSION_MINOR > minor) ||
    (C_VERSION_MAJOR == major && C_VERSION_MINOR == minor && C_VERSION_MICRO > micro)
}

#[derive(Copy, Clone)]
pub struct ScmpArch(u32);

#[derive(PartialEq, Eq, Debug)]
pub struct ScmpAction(u32);

#[derive(PartialEq, Eq, Debug)]
pub struct ScmpSyscall(i32);

pub const ACT_INVALID: ScmpAction = ScmpAction(0);
pub const ACT_KILL: ScmpAction = ScmpAction(1);
pub const ACT_TRAP: ScmpAction = ScmpAction(2);
pub const ACT_ERRNO: ScmpAction = ScmpAction(3);
pub const ACT_TRACE: ScmpAction = ScmpAction(4);
pub const ACT_ALLOW: ScmpAction = ScmpAction(5);

// const arch_start: ScmpArch = ScmpArch(C_ARCH_NATIVE);
// const arch_end: ScmpArch = ScmpArch(C_ARCH_MIPSEL64N32);

impl ScmpAction {
    pub fn set_return_code(&self, code: i16) -> ScmpAction {
        let a_tmp = self.0 & 0x0000FFFF;
        if a_tmp == ACT_ERRNO.0 || a_tmp == ACT_TRACE.0 {
            return ScmpAction(a_tmp | (code as u32 & 0xFFFF) << 16);
        }
        return ScmpAction(self.0);
    }

    pub fn get_return_code(&self) -> i16 {
        return (self.0 >> 16) as i16;
    }
}

fn sanitize_arch(in_arch: ScmpArch) -> Option<()> {
    let arch_start: ScmpArch = ScmpArch(C_ARCH_NATIVE);
    let arch_end: ScmpArch = ScmpArch(C_ARCH_MIPSEL64N32);

    if in_arch.0 < arch_start.0 || in_arch.0 > arch_end.0 {
        return None;
    }

    if in_arch.0 == C_ARCH_BAD {
        return None;
    }
    return Some(());
}

impl ScmpSyscall {
    pub fn get_name(&self) -> Option<String> {
        return self.get_name_by_arch(ScmpArch(C_ARCH_NATIVE));
    }

    pub fn get_name_by_arch(&self, arch: ScmpArch) -> Option<String> {

        if sanitize_arch(arch) == None {
            return Some("".to_string());
        }

        let c_str: *const libc::c_char = unsafe {
            seccomp_syscall_resolve_num_arch(arch.0, self.0 as libc::c_int)
        };
        if c_str == ptr::null() {
            return None;
        }
        return Some(unsafe { CStr::from_ptr(c_str).to_string_lossy().into_owned() });
    }
}


#[cfg(test)]
mod test {

    use super::*;

    #[test]
    fn test_check_version_above_a_certain_one() {
        assert_eq!(true, check_version_above(1, 2, 0));
        assert_eq!(false, check_version_above(2, 1, 0));
        assert_eq!(2, C_VERSION_MAJOR);
        assert_eq!(1, C_VERSION_MINOR);
        assert_eq!(0, C_VERSION_MICRO);
    }

    #[test]
    fn test_action_set_return_code() {
        assert_eq!(ACT_INVALID, ACT_INVALID.set_return_code(0x0010));

        let code_set = ACT_ERRNO.set_return_code(0x0001);
        assert!(ACT_ERRNO != code_set);
        assert!(code_set.get_return_code() == 0x0001);
    }

    #[test]
    fn test_syscall_get_name() {
        let call_1 = ScmpSyscall(0x1);
        let call_fail = ScmpSyscall(0x999);

        let name = call_1.get_name().unwrap();
        let _ = call_fail.get_name().unwrap();
    }

}
