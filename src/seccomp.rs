use libc;
use std::ffi::{CStr, CString};
use std::ptr;
use std::sync::Mutex;

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
}

enum scmp_filter_ctx {}

#[link(name = "seccomp")]
extern "C" {
    fn seccomp_syscall_resolve_num_arch(arch: libc::uint32_t,
                                        syscall: libc::c_int)
                                        -> *const libc::c_char;

    fn seccomp_syscall_resolve_name(name: *const libc::c_char) -> libc::c_int;
    fn seccomp_syscall_resolve_name_arch(arch: libc::uint32_t,
                                         name: *const libc::c_char)
                                         -> libc::c_int;
    fn seccomp_arch_native() -> libc::uint32_t;
    fn seccomp_init(def_action: libc::uint32_t) -> *mut scmp_filter_ctx;
    fn seccomp_release(ctx: *mut scmp_filter_ctx);
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

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct ScmpAction(u32);

#[derive(PartialEq, Eq, Debug)]
pub struct ScmpSyscall(i32);


#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum ScmpCompareOp {
    CompareInvalid,
    CompareNotEqual,
    CompareLess,
    CompareLessOrEqual,
    CompareEqual,
    CompareGreaterEqual,
    CompareGreater,
    CompareMaskedEqual,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct ScmpCondition {
    argument: u32,
    operator: ScmpCompareOp,
    operand_one: u64,
    operand_two: u64,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct ScmpFilter {
    filter_ctx: *mut scmp_filter_ctx,
    valid: bool,
}

pub const ACT_INVALID: ScmpAction = ScmpAction(0);
pub const ACT_KILL: ScmpAction = ScmpAction(1);
pub const ACT_TRAP: ScmpAction = ScmpAction(2);
pub const ACT_ERRNO: ScmpAction = ScmpAction(3);
pub const ACT_TRACE: ScmpAction = ScmpAction(4);
pub const ACT_ALLOW: ScmpAction = ScmpAction(5);

const ActionStart: ScmpAction = ACT_KILL;
const ActionEnd: ScmpAction = ACT_ALLOW;

pub const SCMP_ERROR: libc::c_int = -1;

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum ScmpArch {
    ArchInvalid,
    ArchNative,
    ArchX86,
    ArchAMD64,
    ArchX32,
    ArchARM,
    ArchARM64,
    ArchMIPS,
    ArchMIPS64,
    ArchMIPS64N32,
    ArchMIPSEL,
    ArchMIPSEL64,
    ArchMIPSEL64N32,
}

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
    let arch_start = ScmpArch::ArchNative.to_native();
    let arch_end = ScmpArch::ArchMIPSEL64N32.to_native();

    if in_arch.to_native() < arch_start || in_arch.to_native() > arch_end {
        return None;
    }

    if in_arch.to_native() == C_ARCH_BAD {
        return None;
    }

    return Some(());
}

fn sanitize_action(in_act: ScmpAction) -> Option<()> {
    let in_tmp = in_act.0 & 0x0000FFFF;

    if in_tmp < ActionStart.0 || in_tmp > ActionEnd.0 {
        return None;
    }

    if in_tmp != ACT_TRACE.0 && in_tmp != ACT_ERRNO.0 && (in_tmp & 0xFFFF0000) != 0 {
        return None;
    }

    return Some(());
}

impl ScmpSyscall {
    pub fn get_name(&self) -> Option<String> {
        return self.get_name_by_arch(ScmpArch::ArchNative);
    }

    pub fn get_name_by_arch(&self, arch: ScmpArch) -> Option<String> {

        if sanitize_arch(arch) == None {
            return None;
        }

        let c_str: *const libc::c_char = unsafe {
            seccomp_syscall_resolve_num_arch(arch.to_native(), self.0 as libc::c_int)
        };

        if c_str == ptr::null() {
            return None;
        }

        return Some(unsafe { CStr::from_ptr(c_str).to_string_lossy().into_owned() });
    }
}

impl ScmpArch {
    pub fn to_native(self) -> libc::uint32_t {
        match self {
            ScmpArch::ArchX86 => C_ARCH_X86,
            ScmpArch::ArchAMD64 => C_ARCH_X86_64,
            ScmpArch::ArchX32 => C_ARCH_X32,
            ScmpArch::ArchARM => C_ARCH_ARM,
            ScmpArch::ArchARM64 => C_ARCH_AARCH64,
            ScmpArch::ArchMIPS => C_ARCH_MIPS,
            ScmpArch::ArchMIPS64 => C_ARCH_MIPS64,
            ScmpArch::ArchMIPS64N32 => C_ARCH_MIPS64N32,
            ScmpArch::ArchMIPSEL => C_ARCH_MIPSEL,
            ScmpArch::ArchMIPSEL64 => C_ARCH_MIPSEL64,
            ScmpArch::ArchMIPSEL64N32 => C_ARCH_MIPSEL64N32,
            ScmpArch::ArchNative => C_ARCH_NATIVE,
            ScmpArch::ArchInvalid => C_ARCH_BAD,
        }
    }
}

pub fn get_syscall_from_name(name: &str) -> Option<ScmpSyscall> {
    let c_str = CString::new(name).unwrap();
    let result: libc::c_int = unsafe { seccomp_syscall_resolve_name(c_str.as_ptr()) };
    if result == SCMP_ERROR {
        return None;
    }
    return Some(ScmpSyscall(result));
}

pub fn get_syscall_from_name_by_arch(name: &str, arch: ScmpArch) -> Option<ScmpSyscall> {

    if sanitize_arch(arch) == None {
        return None;
    }

    let c_str = CString::new(name).unwrap();
    let result: libc::c_int = unsafe {
        seccomp_syscall_resolve_name_arch(arch.to_native(), c_str.as_ptr())
    };
    if result == SCMP_ERROR {
        return None;
    }
    return Some(ScmpSyscall(result));
}



pub fn make_condition(arg: u32,
                      comparison: ScmpCompareOp,
                      values: &[u64])
                      -> Option<ScmpCondition> {
    if comparison == ScmpCompareOp::CompareInvalid {
        return None;
    } else if arg > 5 {
        return None;
    } else if values.len() > 2 {
        return None;
    } else if values.len() == 0 {
        return None;
    }

    let cond_struct = ScmpCondition {
        argument: arg,
        operator: comparison,
        operand_one: values[0],
        operand_two: if values.len() == 2 {
            values[1]
        } else {
            0
        },
    };

    return Some(cond_struct);
}

pub fn get_native_arch() -> Option<ScmpArch> {
    let arch = unsafe { seccomp_arch_native() };
    return arch_from_native(arch);
}

fn arch_from_native(a: libc::uint32_t) -> Option<ScmpArch> {
    if a == C_ARCH_X86 {
        Some(ScmpArch::ArchX86)
    } else if a == C_ARCH_X86_64 {
        Some(ScmpArch::ArchAMD64)
    } else if a == C_ARCH_X32 {
        Some(ScmpArch::ArchX32)
    } else if a == C_ARCH_ARM {
        Some(ScmpArch::ArchARM)
    } else if a == C_ARCH_NATIVE {
        Some(ScmpArch::ArchNative)
    } else if a == C_ARCH_AARCH64 {
        Some(ScmpArch::ArchARM64)
    } else if a == C_ARCH_MIPS {
        Some(ScmpArch::ArchMIPS)
    } else if a == C_ARCH_MIPS64 {
        Some(ScmpArch::ArchMIPS64)
    } else if a == C_ARCH_MIPS64N32 {
        Some(ScmpArch::ArchMIPS64N32)
    } else if a == C_ARCH_MIPSEL {
        Some(ScmpArch::ArchMIPSEL)
    } else if a == C_ARCH_MIPSEL64 {
        Some(ScmpArch::ArchMIPSEL64)
    } else if a == C_ARCH_MIPSEL64N32 {
        Some(ScmpArch::ArchMIPSEL64N32)
    } else {
        None
    }
}

pub fn new_filter(default_action: ScmpAction) -> Option<ScmpFilter> {
    if sanitize_action(default_action) == None {
        return None;
    }

    let f_ptr = unsafe { seccomp_init(default_action.0) };

    if f_ptr == ptr::null_mut() {
        return None;
    }

    let filter = ScmpFilter {
        filter_ctx: f_ptr,
        valid: true,
    };

    return Some(filter);
}

impl ScmpFilter {
    pub fn is_valid(&self) -> bool {
        let lock = Mutex::new(*self);
        return self.valid;
    }

    pub fn release(&mut self) {
        let lock = Mutex::new(*self);
        if self.valid {
            return;
        }

        self.valid = false;
        unsafe { seccomp_release(self.filter_ctx) };
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

        let name = call_1.get_name();
        assert!(name != None);
        assert!(name.unwrap().len() > 1);

        assert_eq!(None, call_fail.get_name())
    }

    #[test]
    fn test_syscall_get_name_by_arch() {
        let call_1 = ScmpSyscall(0x1);
        let call_invalid = ScmpSyscall(0x999);

        let arch_good = ScmpArch::ArchAMD64;
        let arch_bad = ScmpArch::ArchInvalid;

        let name = call_1.get_name_by_arch(arch_good);
        assert!(name != None);
        assert_eq!("write", name.unwrap());

        assert_eq!(None, call_1.get_name_by_arch(arch_bad));
        assert_eq!(None, call_invalid.get_name_by_arch(arch_good));
        assert_eq!(None, call_invalid.get_name_by_arch(arch_bad));
    }

    #[test]
    fn test_get_syscall_from_name() {
        let name_1 = "write";
        let name_invalid = "NOTASYSCALL";

        // syscall write should be a valid number, hence not bing None
        let syscall = get_syscall_from_name(name_1);
        assert!(syscall != None);

        // Getting an invalid syscall should be error
        assert_eq!(None, get_syscall_from_name(name_invalid));
    }

    #[test]
    fn test_get_syscall_from_name_by_arch() {
        let name_1 = "write";
        let name_invalid = "NOTASYSCALL";
        let arch_1 = ScmpArch::ArchAMD64;
        let arch_invalid = ScmpArch::ArchInvalid;

        let syscall = get_syscall_from_name_by_arch(name_1, arch_1);
        assert!(syscall != None);

        assert_eq!(None, get_syscall_from_name_by_arch(name_invalid, arch_1));
        assert_eq!(None, get_syscall_from_name_by_arch(name_1, arch_invalid));
        assert_eq!(None,
                   get_syscall_from_name_by_arch(name_invalid, arch_invalid));
    }

    #[test]
    fn test_make_condition() {
        let condition = make_condition(3, ScmpCompareOp::CompareNotEqual, &[0x10]);
        assert!(condition != None);
        let c = condition.unwrap();
        assert_eq!(3, c.argument);
        assert_eq!(0x10, c.operand_one);
        assert_eq!(0, c.operand_two);
        assert_eq!(ScmpCompareOp::CompareNotEqual, c.operator);

        let condition_2 = make_condition(3, ScmpCompareOp::CompareMaskedEqual, &[0x10, 0x20]);
        assert!(condition_2 != None);
        let c_2 = condition_2.unwrap();
        assert_eq!(3, c_2.argument);
        assert_eq!(0x10, c_2.operand_one);
        assert_eq!(0x20, c_2.operand_two);
        assert_eq!(ScmpCompareOp::CompareMaskedEqual, c_2.operator);

        // Bad syscall number of arguments
        assert_eq!(None,
                   make_condition(7, ScmpCompareOp::CompareNotEqual, &[0x10]));
        // Bad comparison operator
        assert_eq!(None,
                   make_condition(3, ScmpCompareOp::CompareInvalid, &[0x10]));
        // More than 2 arguments should fail
        assert_eq!(None,
                   make_condition(3, ScmpCompareOp::CompareMaskedEqual, &[0x10, 0x20, 0x30]));
        // No argument should fail
        assert_eq!(None,
                   make_condition(3, ScmpCompareOp::CompareMaskedEqual, &[]));
    }

    #[test]
    fn test_get_native_arch() {
        let arch = get_native_arch();
        assert!(arch != None);
    }

    #[test]
    fn test_filter_create_release() {
        // Must not create filter with invalid action
        assert_eq!(None, new_filter(ACT_INVALID));

        let filter = new_filter(ACT_KILL);
        assert!(None != filter);

        let mut f = filter.unwrap();
        // Filter must be valid
        assert_eq!(true, f.is_valid());
        f.release();

        // Must be invalid after release
        assert_eq!(false, f.is_valid());
    }

}
