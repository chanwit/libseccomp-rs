extern crate gcc;

fn main() {
    gcc::compile_library("libseccomp_internal.a", &["src/seccomp_internal.c"]);
}
