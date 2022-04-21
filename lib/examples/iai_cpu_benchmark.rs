use atomic_lib::Storelike;

use iai::{black_box, Iai};

fn bench_empty(iai: &mut Iai) {
    iai.run(|| {
        let store = atomic_lib::Store::init().unwrap();
        return;
    });
}

fn bench_all_resources(iai: &mut Iai) {
    iai.run(|| {
        let store = atomic_lib::Store::init().unwrap();
        store.all_resources(black_box(true)).len();
    });
}

iai::main!(bench_empty, bench_all_resources);
