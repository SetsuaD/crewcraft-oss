// T112: tokenizer and an AND, prefix-matching, newest-first search index.
#![allow(clippy::unwrap_used)] // helper functions outside #[test] unwrap too
use crewcraft_server_core::search::{Index, terms};

fn v(x: &[&str]) -> Vec<String> {
    x.iter().map(|s| s.to_string()).collect()
}

fn idx() -> Index {
    let mut i = Index::new();
    i.insert(1, "Deploy the server tonight");
    i.insert(2, "server is down");
    i.insert(3, "Tonight we deploy again");
    i.insert(4, "lunch?");
    i
}

const NONE: Vec<u64> = Vec::new();

#[test]
fn terms_split_lowercase_and_drop_short_ones() {
    assert_eq!(terms("Hello, World! a b ok"), v(&["hello", "world", "ok"]));
    assert_eq!(terms("Ça va? Größe-42"), v(&["ça", "va", "größe", "42"]));
    assert_eq!(terms("ok ok"), v(&["ok", "ok"]));
    assert_eq!(terms(""), v(&[]));
}

#[test]
fn every_term_must_match_newest_first() {
    let i = idx();
    assert_eq!(i.search("deploy tonight", 10), vec![3, 1]);
    assert_eq!(i.search("server", 10), vec![2, 1]);
    assert_eq!(i.search("SERVER down", 10), vec![2]);
    assert_eq!(i.search("pizza", 10), NONE);
}

#[test]
fn query_terms_match_as_prefixes() {
    let i = idx();
    assert_eq!(i.search("dep", 10), vec![3, 1]);
    assert_eq!(i.search("lun", 10), vec![4]);
    assert_eq!(i.search("eploy", 10), NONE);
}

#[test]
fn limits_and_empty_queries() {
    let i = idx();
    assert_eq!(i.search("server", 1), vec![2]);
    assert_eq!(i.search("server", 0), NONE);
    assert_eq!(i.search("a ?", 10), NONE);
}

#[test]
fn reindexing_replaces_and_remove_forgets() {
    let mut i = idx();
    i.insert(2, "all good now");
    assert_eq!(i.search("server", 10), vec![1]);
    assert_eq!(i.search("good", 10), vec![2]);
    i.remove(1);
    assert_eq!(i.search("server", 10), NONE);
    i.remove(99);
    assert_eq!(i.search("tonight", 10), vec![3]);
}
