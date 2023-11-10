use std::rc::Rc;

use accumulators::{
    hasher::stark_poseidon::StarkPoseidonHasher, mmr::MMR, store::memory::InMemoryStore,
};

#[test]
fn should_discard_properly() {
    let store = InMemoryStore::default();
    let store = Rc::new(store);
    let hasher = StarkPoseidonHasher::new(Some(false));

    let mut ref_mmr = MMR::new(store.clone(), hasher.clone(), None);
    ref_mmr.append("1".to_string()).expect("Failed to append");
    ref_mmr.append("2".to_string()).expect("Failed to append");
    ref_mmr.append("3".to_string()).expect("Failed to append");
    ref_mmr.append("4".to_string()).expect("Failed to append");
    ref_mmr.append("5".to_string()).expect("Failed to append");
    let _ref_eg_for_proving = ref_mmr.append("6".to_string()).expect("Failed to append");
    ref_mmr.append("7".to_string()).expect("Failed to append");
    ref_mmr.append("8".to_string()).expect("Failed to append");
    let ref_bag = ref_mmr.bag_the_peaks(None).unwrap();
    let ref_root = ref_mmr
        .calculate_root_hash(&ref_bag, ref_mmr.elements_count.get())
        .expect("Failed to calculate root hash");

    let mut draft = ref_mmr.start_draft();
    draft.mmr.append("9".to_string()).expect("Failed to append");
    let draft_bag = draft.mmr.bag_the_peaks(None).unwrap();
    let draft_root = draft
        .mmr
        .calculate_root_hash(&draft_bag, draft.mmr.elements_count.get())
        .expect("Failed to calculate root hash");
    draft.discard();

    let ref_after_bag = ref_mmr.bag_the_peaks(None).unwrap();
    let ref_after_root = ref_mmr
        .calculate_root_hash(&ref_after_bag, ref_mmr.elements_count.get())
        .expect("Failed to calculate root hash");
    assert_eq!(ref_root, ref_after_root);

    ref_mmr.append("9".to_string()).expect("Failed to append");
    let ref_after_bag = ref_mmr.bag_the_peaks(None).unwrap();
    let ref_after_root = ref_mmr
        .calculate_root_hash(&ref_after_bag, ref_mmr.elements_count.get())
        .expect("Failed to calculate root hash");
    assert_eq!(draft_root, ref_after_root);
}

#[test]
fn should_apply() {
    let store = InMemoryStore::default();
    let store = Rc::new(store);
    let hasher = StarkPoseidonHasher::new(Some(false));

    let mut mmr = MMR::new(store.clone(), hasher.clone(), None);
    mmr.append("1".to_string()).expect("Failed to append");
    mmr.append("2".to_string()).expect("Failed to append");
    mmr.append("3".to_string()).expect("Failed to append");
    mmr.append("4".to_string()).expect("Failed to append");
    mmr.append("5".to_string()).expect("Failed to append");
    mmr.append("6".to_string()).expect("Failed to append");
    mmr.append("7".to_string()).expect("Failed to append");
    mmr.append("8".to_string()).expect("Failed to append");

    let mut draft = mmr.start_draft();
    let eg_value = "9".to_string();
    let eg_append = draft
        .mmr
        .append(eg_value.clone())
        .expect("Failed to append");
    let draft_bag = draft.mmr.bag_the_peaks(None).unwrap();
    let draft_root = draft
        .mmr
        .calculate_root_hash(&draft_bag, draft.mmr.elements_count.get())
        .expect("Failed to calculate root hash");
    draft.commit();

    let bag = mmr.bag_the_peaks(None).unwrap();
    let root = mmr
        .calculate_root_hash(&bag, mmr.elements_count.get())
        .expect("Failed to calculate root hash");
    assert_eq!(draft_root, root);

    mmr.append("10".to_string()).expect("Failed to append");

    let proof = mmr
        .get_proof(eg_append.element_index, None)
        .expect("Failed to get proof");
    assert!(mmr
        .verify_proof(proof, eg_value, None)
        .expect("Failed to verify proof"));
}
