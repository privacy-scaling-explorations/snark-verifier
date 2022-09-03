pub mod arithmetic;
pub mod expression;
pub mod msm;
pub mod transcript;

pub(crate) use itertools::Itertools;

#[macro_export]
macro_rules! collect_slice {
    ($vec:ident) => {
        use $crate::util::Itertools;

        let $vec = $vec.iter().map(|vec| vec.as_slice()).collect_vec();
    };
    ($vec:ident, 2) => {
        use $crate::util::Itertools;

        let $vec = $vec
            .iter()
            .map(|vec| {
                collect_slice!(vec);
                vec
            })
            .collect_vec();
        let $vec = $vec.iter().map(|vec| vec.as_slice()).collect_vec();
    };
}
