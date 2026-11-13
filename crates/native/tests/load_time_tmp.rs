// TEMP: time loading and preparing an image (never run).
use std::time::Instant;

#[test]
#[ignore]
fn load_time() {
    let path = std::env::var("LOAD_BENCH").unwrap();
    let data = std::fs::read(path).unwrap();
    let elf = fwe_elf::Elf::parse(&data).unwrap();
    let page = 16384;
    for _ in 0..4 {
        let t = Instant::now();
        let r = elf.unwind_code_ranges();
        eprintln!("unwind ranges {:?}: {}", t.elapsed(), r.map_or(0, |r| r.len()));
        let t = Instant::now();
        fwe_native::loader::load(&elf, page, |a, l, known, arena| {
            let t = Instant::now();
            // SAFETY: memory the loader just mapped writable; never run.
            let s = unsafe { fwe_native::prepare::prepare(a, l, 8, 16, page, Some(arena), known) };
            eprintln!("  prepare {a:#x}+{l:#x}: {:?} {:?}", t.elapsed(), s);
            Ok(())
        })
        .unwrap();
        eprintln!("load total {:?}", t.elapsed());
    }
}

#[test]
#[ignore]
fn patch_time() {
    let path = std::env::var("LOAD_BENCH").unwrap();
    let data = std::fs::read(path).unwrap();
    let elf = fwe_elf::Elf::parse(&data).unwrap();
    let (vaddr, size) = elf.exec_ranges().into_iter().max_by_key(|r| r.1).unwrap();
    let off = elf.loads().find(|p| p.executable()).map(|p| vaddr - p.vaddr + p.offset).unwrap();
    let code0 = data[off as usize..(off + size) as usize].to_vec();
    let known: Vec<(u64, u64)> = elf
        .unwind_code_ranges()
        .unwrap()
        .into_iter()
        .filter_map(|(a, l)| (a >= vaddr && a < vaddr + size).then(|| (a - vaddr, l)))
        .collect();
    for _ in 0..4 {
        let mut code = code0.clone();
        let t = Instant::now();
        let p = fwe_native::rewrite::patch(&mut code, Some(&known));
        eprintln!("patch {:?} sites {}", t.elapsed(), p.sites.len());
        let t = Instant::now();
        let n = fwe_native::rewrite::count_sites(&code0);
        eprintln!("count {:?} {n}", t.elapsed());
    }
}
