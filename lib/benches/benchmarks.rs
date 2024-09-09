//! Various benchmarks for atomic_lib.
//! Should be run using `cargo criterion` or `cargo bench --all-features`.
//! See contribute.md for more information.

use atomic_lib::utils::random_string;
use atomic_lib::*;
use criterion::{criterion_group, criterion_main, Criterion};

fn random_atom_string() -> Atom {
    Atom::new(
        format!("https://localhost/{}", random_string(10)),
        urls::DESCRIPTION.into(),
        Value::Markdown(random_string(200)),
    )
}

fn random_subject() -> String {
    format!("https://localhost/{}", random_string(10))
}

fn random_array(n: usize) -> Vec<String> {
    (0..n).map(|_| random_subject()).collect()
}

fn random_atom_array() -> Atom {
    Atom::new(
        format!("https://localhost/{}", random_string(10)),
        urls::COLLECTION_MEMBERS.into(),
        random_array(200).into(),
    )
}

fn random_resource(atom: &Atom) -> Resource {
    let mut resource = Resource::new(atom.subject.clone());
    resource.set_unsafe(atom.property.clone(), atom.value.clone());
    resource
}

fn criterion_benchmark(c: &mut Criterion) {
    let store = Db::init_temp("bench").unwrap();

    c.bench_function("add_resource", |b| {
        b.iter(|| {
            let resource = random_resource(&random_atom_string());
            store
                .add_resource_opts(&resource, true, true, false)
                .unwrap();
        })
    });

    c.bench_function("resource.save() string", |b| {
        b.iter(|| {
            let mut resource = random_resource(&random_atom_string());
            resource.save(&store).unwrap();
        })
    });

    c.bench_function("resource.save() array", |b| {
        b.iter(|| {
            let mut resource = random_resource(&random_atom_array());
            resource.save(&store).unwrap();
        })
    });

    let big_resource = store
        .get_resource_extended(
            "https://localhost/collections",
            false,
            &agents::ForAgent::Public,
        )
        .unwrap();

    c.bench_function("resource.to_json_ad()", |b| {
        b.iter(|| {
            big_resource.to_json_ad().unwrap();
        })
    });

    c.bench_function("resource.to_json_ld()", |b| {
        b.iter(|| {
            big_resource.to_json_ld(&store).unwrap();
        })
    });

    c.bench_function("resource.to_json()", |b| {
        b.iter(|| {
            big_resource.to_json(&store).unwrap();
        })
    });

    c.bench_function("resource.to_n_triples()", |b| {
        b.iter(|| {
            big_resource.to_n_triples(&store).unwrap();
        })
    });

    c.bench_function("all_resources()", |b| {
        b.iter(|| {
            let _all = store.all_resources(false).collect::<Vec<Resource>>();
        })
    });

    store.clear_all_danger().unwrap();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
