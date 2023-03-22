pub trait TupleAppend<X> {
    type Output;
    fn append(self, t: X) -> Self::Output;
}

impl<X> TupleAppend<X> for () {
    type Output = (X,);
    fn append(self, x: X) -> Self::Output {
        (x,)
    }
}

pub trait HasId {
    type Target: ?Sized;

    fn id(&self) -> u8;
    fn get(&self) -> &Self::Target;
    fn get_mut(&mut self) -> &mut Self::Target;
}

pub trait TupleById<Target: ?Sized> {
    fn get_by_id_mut(&mut self, id: u8) -> Option<&mut Target>;

    fn get_by_pos(&self, idx: usize) -> Option<&Target>;

    fn get_by_pos_mut(&mut self, idx: usize) -> Option<&mut Target>;
    // Note: This can not be done via standard iterator, because of target type.
    fn iter(&mut self) -> TupleByIdIterator<Self, Target>;
}

impl<Target> TupleById<Target> for () {
    fn get_by_id_mut(&mut self, _id: u8) -> Option<&mut Target> {
        None
    }

    fn get_by_pos(&self, _idx: usize) -> Option<&Target> {
        None
    }

    fn get_by_pos_mut(&mut self, _idx: usize) -> Option<&mut Target> {
        None
    }

    fn iter(&mut self) -> TupleByIdIterator<Self, Target> {
        TupleByIdIterator {
            idx: 0,
            inner: self,
            _marker: std::marker::PhantomData,
        }
    }
}

pub struct TupleByIdIterator<'a, I: ?Sized, Target: ?Sized> {
    idx: usize,
    inner: &'a I,
    _marker: std::marker::PhantomData<Target>,
}

impl<'a, I, Target: ?Sized + 'a> Iterator for TupleByIdIterator<'a, I, Target>
where
    I: TupleById<Target>,
{
    type Item = &'a Target;

    fn next(&mut self) -> Option<Self::Item> {
        let res = self.inner.get_by_pos(self.idx);
        self.idx += 1;

        res
    }
}

macro_rules! tuple_impl {
    ($($n:ident),+) => {
        #[allow(non_snake_case)]
        impl<$($n),+, X> TupleAppend<X> for ($($n),+,) {
            type Output = ($($n),+, X);
            fn append(self, x : X) -> Self::Output {
                let ($($n),+,) = self;
                ($($n),+, x)
            }
        }

        #[allow(non_snake_case)]
        impl<$($n),+, Target : ?Sized> TupleById<Target> for ($($n),+,)
        where
            $($n: HasId<Target = Target>,)+
        {
            fn get_by_id_mut(&mut self, id: u8) -> Option<&mut Target> {
                let ($($n),+,) = self;
                $(
                    if $n.id() == id {
                        return Some($n.get_mut());
                    }
                )+

                None
            }

            fn get_by_pos(&self, idx: usize) -> Option<&Target> {
                let counter = 0;
                let ($($n),+,) = self;
                $(
                    if counter == idx {
                        return Some($n.get());
                    }
                    let counter = counter + 1;
                )+

                let _ = counter;
                None
            }

            fn get_by_pos_mut(&mut self, idx: usize) -> Option<&mut Target> {
                let counter = 0;
                let ($($n),+,) = self;
                $(
                    if counter == idx {
                        return Some($n.get_mut());
                    }
                    let counter = counter + 1;
                )+

                let _ = counter;
                None
            }

            fn iter(&mut self) -> TupleByIdIterator<Self, Target> {
                TupleByIdIterator {
                    idx: 0,
                    inner: self,
                    _marker: std::marker::PhantomData,
                }
            }
        }

    };
}

tuple_impl!(A);
tuple_impl!(A, B);
tuple_impl!(A, B, C);
tuple_impl!(A, B, C, D);
tuple_impl!(A, B, C, D, E);
tuple_impl!(A, B, C, D, E, F);
tuple_impl!(A, B, C, D, E, F, G);
tuple_impl!(A, B, C, D, E, F, G, H);
tuple_impl!(A, B, C, D, E, F, G, H, I);
tuple_impl!(A, B, C, D, E, F, G, H, I, J);

#[cfg(test)]
mod tests {
    use super::*;

    struct A;
    struct B;

    trait MyTrait {
        fn say_my_name(&self) -> &'static str;
    }

    impl MyTrait for A {
        fn say_my_name(&self) -> &'static str {
            "A"
        }
    }
    impl MyTrait for B {
        fn say_my_name(&self) -> &'static str {
            "B"
        }
    }

    impl HasId for A {
        type Target = dyn MyTrait;

        fn id(&self) -> u8 {
            10
        }

        fn get(&self) -> &Self::Target {
            self
        }

        fn get_mut(&mut self) -> &mut Self::Target {
            self
        }
    }

    impl HasId for B {
        type Target = dyn MyTrait;

        fn id(&self) -> u8 {
            20
        }

        fn get(&self) -> &Self::Target {
            self
        }

        fn get_mut(&mut self) -> &mut Self::Target {
            self
        }
    }

    #[test]
    fn test_tuple_append() {
        let t = (1u8, 2u16, 3u32);
        let t = t.append(4u64);
        assert_eq!(t, (1, 2, 3, 4));
    }

    #[test]
    fn test_tuple_by_id() {
        let mut t = (A, B);

        let a = t.get_by_id_mut(10).unwrap();
        assert_eq!(a.say_my_name(), "A");

        let b = t.get_by_id_mut(20).unwrap();
        assert_eq!(b.say_my_name(), "B");

        let c = t.get_by_id_mut(0);
        assert!(c.is_none());
    }

    #[test]
    fn test_tuple_by_pos() {
        let mut t = (A, B);

        let a = t.get_by_pos(0).unwrap();
        assert_eq!(a.say_my_name(), "A");

        let b = t.get_by_pos(1).unwrap();
        assert_eq!(b.say_my_name(), "B");

        let c = t.get_by_pos(2);
        assert!(c.is_none());

        let a = t.get_by_pos_mut(0).unwrap();
        assert_eq!(a.say_my_name(), "A");

        let b = t.get_by_pos_mut(1).unwrap();
        assert_eq!(b.say_my_name(), "B");

        let c = t.get_by_pos_mut(2);
        assert!(c.is_none());
    }
}