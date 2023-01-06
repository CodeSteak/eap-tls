// https://boats.gitlab.io/blog/post/wakers-i/

use core::cell::Cell;
use core::task::Context;
use core::task::Poll;
use core::task::Waker;
use core::{
    cell::RefCell,
    future::{self, Future},
    marker::PhantomData,
    ops::Deref,
    pin::Pin,
};
mod context {
    use std::task::{RawWaker, RawWakerVTable};

    pub unsafe fn clone_raw_waker(_: *const ()) -> RawWaker {
        RawWaker::new(
            std::ptr::null(),
            &RawWakerVTable::new(clone_raw_waker, wake, wake_by_ref, drop_raw_waker),
        )
    }

    unsafe fn wake(_: *const ()) {}

    unsafe fn wake_by_ref(_: *const ()) {}

    unsafe fn drop_raw_waker(_: *const ()) {}
}

struct Executer<'a, I, O, F: Future<Output = ()>> {
    inner: Pin<Box<F>>,
    ctx: StateMachineContext<'a, I, O>,
}

struct StateMachineContext<'a, I, O> {
    incomming: &'a Cell<Option<I>>,
    outgoing: &'a Cell<Option<O>>,
}

impl<I, O> Clone for StateMachineContext<'_, I, O> {
    fn clone(&self) -> Self {
        Self {
            incomming: self.incomming,
            outgoing: self.outgoing,
        }
    }
}

impl<'a, I, O, F: Future<Output = ()>> Executer<'a, I, O, F> {
    fn new(future: F, ctx: StateMachineContext<'a, I, O>) -> Self {
        let i = ctx.clone();
        Self {
            inner: Box::pin(future),
            ctx,
        }
    }

    fn step<'b>(&'b mut self, input: I) -> ExecuterIterator<'b, 'a, I, O, F> {
        let waker = unsafe { Waker::from_raw(context::clone_raw_waker(std::ptr::null())) };
        let mut ctx = Context::from_waker(&waker);

        self.ctx.incomming.replace(Some(input));

        ExecuterIterator { executer: self }
    }
}

struct ExecuterIterator<'b, 'a, I, O, F: Future<Output = ()>> {
    executer: &'b mut Executer<'a, I, O, F>,
}

impl<'b, 'a, I, O, F: Future<Output = ()>> Iterator for ExecuterIterator<'b, 'a, I, O, F> {
    type Item = O;

    fn next(&mut self) -> Option<Self::Item> {
        let waker = unsafe { Waker::from_raw(context::clone_raw_waker(std::ptr::null())) };
        let mut ctx = Context::from_waker(&waker);

        match Pin::new(&mut self.executer.inner).poll(&mut ctx) {
            Poll::Ready(output) => return None,
            Poll::Pending => {
                let output = self.executer.ctx.outgoing.replace(None);
                return output;
            }
        };
    }
}

impl<'a, I, O> StateMachineContext<'a, I, O> {
    async fn next_event(&self) -> I {
        loop {
            if let Some(msg) = self.incomming.replace(None) {
                return msg;
            }

            yield_once().await;
        }
    }

    async fn send(&self, msg: O) {
        loop {
            let old = self.outgoing.replace(None);
            if old.is_none() {
                self.outgoing.replace(Some(msg));
                return;
            } else {
                // Put back
                self.outgoing.replace(old);
            }

            yield_once().await;
        }
    }
}

async fn yield_once() {
    YieldOnceFuture(false).await;
}

struct YieldOnceFuture(bool);
impl Future for YieldOnceFuture {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
        if self.0 {
            Poll::Ready(())
        } else {
            self.0 = true;
            Poll::Pending
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum TrafficLight {
    Red,
    Yellow,
    Green,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum TrafficEvent {
    Tick,
    Button,
}

///////////////////////
///
///
///
///
///
///////////////////////

async fn traffic_light(ctx: StateMachineContext<'_, TrafficEvent, TrafficLight>) {
    loop {
        ctx.send(TrafficLight::Red).await;
        while ctx.next_event().await != TrafficEvent::Button {
            // NOP
        }

        ctx.send(TrafficLight::Yellow).await;
        while ctx.next_event().await != TrafficEvent::Tick {
            // NOP
        }

        ctx.send(TrafficLight::Red).await;
        while ctx.next_event().await != TrafficEvent::Tick {
            // NOP
        }
        ctx.send(TrafficLight::Green).await;
    }
}

fn main() {
    let ctx = StateMachineContext {
        incomming: &Cell::new(None),
        outgoing: &Cell::new(None),
    };

    // TODO : USE PIN MACRO.
    let mut state =
        Executer::<'_, TrafficEvent, TrafficLight, _>::new(traffic_light(ctx.clone()), ctx);

    for e in [
        TrafficEvent::Tick,
        TrafficEvent::Tick,
        TrafficEvent::Button,
        TrafficEvent::Tick,
        TrafficEvent::Tick,
        TrafficEvent::Button,
    ] {
        println!("Event: {e:?}");
        let events = state.step(e);
        for s in events {
            println!("\t-> {s:?}");
        }
    }
}
