//! Various benchmarks for atomic_lib.
//! Should be run using `cargo bench`.
//! Add features here

use atomic_lib::*;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};

fn random_string(n: usize) -> String {
    let rand_string: String = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(n)
        .map(char::from)
        .collect();
    rand_string
}

fn random_atom() -> Atom {
    Atom::new(
        format!("https://localhost/{}", random_string(10)),
        urls::DESCRIPTION.into(),
        Value::Markdown(random_string(200)),
    )
}

fn random_resource(atom: &Atom) -> Resource {
    let mut resource = Resource::new(atom.subject.clone());
    resource.set_propval_unsafe(atom.property.clone(), atom.value.clone());
    resource
}

fn criterion_benchmark(c: &mut Criterion) {
    let store = Db::init_temp("bench").unwrap();

    c.bench_function("add_atom_to_index", |b| {
        b.iter(|| {
            let atom = random_atom();
            let resource = random_resource(&random_atom());
            store.add_atom_to_index(&atom, &resource).unwrap();
        })
    });

    c.bench_function("add_resource", |b| {
        b.iter(|| {
            let resource = random_resource(&random_atom());
            store
                .add_resource_opts(&resource, true, true, false)
                .unwrap();
        })
    });

    c.bench_function("resource.save()", |b| {
        b.iter(|| {
            let mut resource = random_resource(&random_atom());
            resource.save(&store).unwrap();
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
