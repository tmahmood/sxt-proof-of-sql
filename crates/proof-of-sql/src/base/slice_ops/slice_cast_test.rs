use super::*;
use crate::base::scalar::test_scalar::TestScalar;
#[test]
fn test_slice_map_to_vec() {
    let a: Vec<u32> = vec![1, 2, 3, 4];
    let b: Vec<u64> = vec![1, 2, 3, 4];
    let a: Vec<u64> = slice_cast_with(&a, |&x| u64::from(x));
    assert_eq!(a, b);
}

/// random test for [`slice_cast_with`]
#[test]
fn test_slice_cast_with_random() {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let a: Vec<u32> = (0..100).map(|_| rng.gen()).collect();
    let b: Vec<u64> = a.iter().map(|&x| u64::from(x)).collect();
    let a: Vec<u64> = slice_cast_with(&a, |&x| u64::from(x));
    assert_eq!(a, b);
}

/// random test casting from integer to `TestScalar`
#[test]
fn test_slice_cast_with_random_from_integer_to_testscalar() {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let a: Vec<u32> = (0..100).map(|_| rng.gen()).collect();
    let b: Vec<TestScalar> = a.iter().map(|&x| TestScalar::from(x)).collect();
    let a: Vec<TestScalar> = slice_cast_with(&a, |&x| TestScalar::from(x));
    assert_eq!(a, b);
}

/// random test auto casting from integer to `TestScalar`
#[test]
fn test_slice_cast_random_from_integer_to_testscalar() {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let a: Vec<u32> = (0..100).map(|_| rng.gen()).collect();
    let b: Vec<TestScalar> = a.iter().map(|&x| TestScalar::from(x)).collect();
    let a: Vec<TestScalar> = slice_cast(&a);
    assert_eq!(a, b);
}

/// Test that mut cast does the same as vec cast
#[test]
fn test_slice_cast_mut() {
    let a: Vec<u32> = vec![1, 2, 3, 4];
    let mut b: Vec<u64> = vec![0, 0, 0, 0];
    slice_cast_mut_with(&a, &mut b, |&x| u64::from(x));
    assert_eq!(b, slice_cast_with(&a, |&x| u64::from(x)));
}

/// random test for [`slice_cast_mut_with`]
#[test]
fn test_slice_cast_mut_with_random() {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let a: Vec<u32> = (0..100).map(|_| rng.gen()).collect();
    let mut b: Vec<u64> = vec![0; 100];
    slice_cast_mut_with(&a, &mut b, |&x| u64::from(x));
    assert_eq!(b, slice_cast_with(&a, |&x| u64::from(x)));
}

/// random test for [`slice_cast_mut_with`]
#[test]
fn test_slice_cast_mut_random() {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let a: Vec<u32> = (0..100).map(|_| rng.gen()).collect();
    let mut b: Vec<TestScalar> = vec![TestScalar::default(); 100];
    slice_cast_mut(&a, &mut b);
    assert_eq!(b, slice_cast(&a));
}
