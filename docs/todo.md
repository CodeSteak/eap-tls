# Statemachines HOWTO?
- Embedded TLS
- async / await
- Enums?
- Crates
- Generics
- Closures

## Enums 
Blogpost: 
https://hoverbear.org/blog/rust-state-machine-pattern/

```rust
struct StateMachine {
    state: State,
}

enum State {
    A,
    B,
    C,
}

impl StateMachine {
    fn new() -> Self {
        StateMachine { state: State::A }
    }

    fn next(&mut self) {
        match self.state {
            State::A => self.state = {
              ...
              self.state = State::B;
            },
            State::B => ...,
            State::C => ...,
        }
    }
}
```
Problem: Recht verbos, riesige match-Blöcke sind unübersichtlich.

## State Traits

Blogpost: 
- https://blog.yoshuawuyts.com/state-machines/

```rust
struct StateMachine<S:State> {
    state: S,
}

trait State {
    fn next(self) -> Self;
}

impl StateMachine {
    fn new() -> Self {
        StateMachine { state: A }
    }

    fn next(&mut self) {
        self.state = self.state.next();
    }
}

struct A;
struct B;
struct C;

impl State for A {
    fn next(self) -> Self {
        B
    }
}
 
...
```
Pro: Recht übersichtlich, keine riesigen match-Blöcke. States getrennt von StateMachine.
Contra: 
  - Benötigt Memory für jeden State transition eine Memory-Allocation. 
    - PhantomData mit 'globalen' vars in `StateMachine`?, doof weil dann StateMachine irgendwie dyn sein muss.
    - Alternativ: Traits in Enum wrappen, leider recht redundant.
      https://crates.io/crates/enum_dispatch
      https://docs.rs/trait_enum/latest/trait_enum/
    - Ist zero sized dispatch möglich? -- Falls ja dann kann aber immernoch kein State in Zuständen gespeichert werden. 

  - Wie kann 'Shared State' in StateMachine gehalten werden? 
    Für enum dispatch möglich, aber doof weil matching nötig,
    und borrow checker sagt vlcht nein.
    ```rust
    impl State for A {
      fn next(me : &mut StateMachine) {
        let StateVarients::A(a) = me.state else { panic!() }; // <- doof
      }
    }
    ```
    Daher shared state in StateMachine, und dann in State übergeben.
    ```rust
    struct StateMachine<S:State> {
        state: S,
        shared_state: SharedState,
    }

     impl State for A {
      fn next(me : &mut StateMachine, shared_state: &mut SharedState) {
        ...
      }
    }
    ```

## Crates 
- https://lib.rs/crates/rs_state_machine
  Auszug:
  ```rust
  fn main() {
    let light_switch = define!(
        "OFF" - "TURN_ON"  -> "ON",
        "ON"  - "TURN_OFF" -> "OFF"
    );
  }

  fn main() {
    let mut enum_light_switch = Machine::new();
    enum_light_switch.add_transition(Transition::new(LightState::Off, LightEvent::TurnOn, LightState::On));
    enum_light_switch.add_transition(Transition::new(LightState::On, LightEvent::TurnOff, LightState::Off));
    let mut state_light = StatefulLight { state: LightState::Off };

    enum_light_switch.apply(&mut state_light, LightEvent::TurnOn);
  }
  ```

## Async / Await
Basics: https://fasterthanli.me/articles/understanding-rust-futures-by-going-way-too-deep

-> see ./starter 


### Crates

https://lib.rs/crates/state_machine_future
- Boilerplate siehe examples in crate
- Eher nicht so embedded freundlich.

## Clojures
// TODO: Src?

```rust
type ClojureFn = Fn(e : Event) -> Box<ClojureFn>

struct StateMachine {
    state: Box<ClojureFn>,
}

impl StateMachine {
    fn next(&mut state) -> {
      self.state = self.state();
    }
}

fn start_state(e : Event) {

  ...
  let x = 42;
  return Box::new(move |e| next_state(e,x))
}

fn next_state(e: Event, context : u8) {
  ...
}
```

Pro: 
- Kaum Boilerplate 

Contra:
- Entweder kein State oder 1x Allocation per Event. 

----

## Auswahl

Die Enum scheint am besten geeignet zu sein. Boilerplate ist ein kleines Problem bei der geringen Anzahl an States und hohen Komplexität der States. 
Einzelne Event könnten sogar als einzelne Methoden implementiert werden, weil diese in einer Request-Response, was die Lesbarkeit noch erhöhen würde. Es sind keine Allocations notwendig. 

Enum Dispatch scheint auch eine gute Lösung zu sein, um den restlichen Boilerplate zu reduzieren.




# Aktivitätsdiagramm machen

<img src="./diagramme/activity.jpg">


# Diagram welche Schichten haben welche Variablen?

siehe [./StateMachine.md](./StateMachine.md)


# Statemaschine "aufzeichnen"

Drei Schichten:

- EAP-Layer
- Auth/Peer-Layer
- Method-Layer(s)

Die EAP-Layer unterscheiden sich kaum. Einziger Unterscheid ist 
der zu erwartende Message-Typ. Bei Peer: Req, bei Server: Resp.
Beim senden ist es umgekehrt.

Die Auth/Peer-Layer unterscheiden sich stark.

Die einzelenen Methoden sind recht simpel, aber Peer und Server haben hier unterschiedliche Rollen => Getrennte Implementierung.


## [Eigene -> ./StateMachine.md](./StateMachine.md)



## Aus: [RFC4137](https://www.rfc-editor.org/rfc/rfc4137.pdf)

<img src="./diagramme/rfc4137-peer.png">

<img src="./diagramme/rfc4137-auth.png">

---

# TODO Jan. Woche 2 - Präsentationsentwurf.

