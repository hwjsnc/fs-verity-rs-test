use fs_verity::InnerHashAlgorithm;
use fs_verity::linux::{fsverity_enable, fsverity_measure};
use std::fs::File;
use std::io::Write as _;
use std::os::fd::AsRawFd as _;
use std::process::Command;

fn check(
    filename: &str,
    content: &[u8],
    block_size: usize,
    algo: InnerHashAlgorithm,
    salt: &[u8],
    expected_hash: &str,
) {
    let mut file = File::create_new(filename).unwrap();
    file.write_all(content).unwrap();
    file.sync_all().unwrap();
    let ro_file = File::open(format!("/proc/self/fd/{}", file.as_raw_fd())).unwrap();
    drop(file);
    fsverity_enable(ro_file.as_raw_fd(), block_size, algo, salt).unwrap();
    let (algo, _value) = fsverity_measure(ro_file.as_raw_fd()).unwrap();
    println!("fs-verity enabled on file {filename:?}, algo {algo:?}, block size {block_size}");
    let expected_verity_output = format!("{expected_hash} {filename}\n").into_bytes();
    let actual_verity_output = Command::new("/usr/bin/fsverity")
        .args(["measure", "--", filename])
        .output()
        .unwrap()
        .stdout;
    assert_eq!(&expected_verity_output, &actual_verity_output);
}

fn main() {
    check(
        "helloworld.txt",
        b"hello, world\n",
        4096,
        InnerHashAlgorithm::Sha256,
        &[],
        "sha256:8b174f1ec58f607df27386a4485c66913251da99af628e87dd62968cddd6bbc1",
    );

    check(
        "random1.dat",
        include_bytes!("../random1.dat"),
        4096,
        InnerHashAlgorithm::Sha256,
        &[],
        "sha256:ecc777344e159279c327238fb2dde22007e82c69fdc5112df52437401b1e4c2d",
    );

    check(
        "random2.dat",
        include_bytes!("../random2.dat"),
        2048,
        InnerHashAlgorithm::Sha512,
        &[
            0xdd, 0x1e, 0x58, 0x51, 0x16, 0x50, 0x6e, 0x80, 0x1b, 0xf5, 0x2a, 0xd1, 0x64, 0x72,
            0x77, 0x90, 0xd9, 0xdc, 0xb3, 0xa8, 0x1c, 0x62, 0x3c, 0xcb, 0xd3, 0xf3, 0xe8, 0x5f,
            0x61, 0x78, 0xeb, 0x38,
        ], // random 32 byte salt
        "sha512:52412a2c1f35867522256475f56463adf0ad209f969f7fb53817ff32a99267c53d3325d62c17cda73728d51423f43e689b7e8c8f96288ab013cb8baeace62e59",
    );
}
