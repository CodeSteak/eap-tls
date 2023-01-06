# Authentikator 

## EAP-Layer

> The EAP layer receives and transmits EAP packets via the lower layer, implements duplicate detection and retransmission, and delivers and receives EAP messages to and from the EAP peer and authenticator layers.
-- 2.2.  EAP Multiplexing Model, RFC 3748

### Idle

State:
- id: int

|Event|Cond|Action|Next|
|-----|----|------|----|
|Recv || fail -> UPPER |-|
|Timeout || - |-|
|send(type=success,body) || id++ <br/> msg = build_package(..)  <br/> msg -> LOWER   |Finished|
|send(type,body) || id++ <br/> msg = build_package(..)  <br/> msg -> LOWER   |RequestSent(id,last_msg=msg)|


### RequestSent

State:
- id: int
- retransmission_counter: int
- last_msg : bytes

|Event|Cond|Action|Next|
|-----|----|------|----|
|Recv| valid | recv(body) -> UPPER |Idle|
|Recv| else     | fail -> UPPER|Idle|
|Timeout| retransmission_counter < ~3-5 | retransmission_counter++ <br/> last_msg -> LOWER  |-|
|Timeout| else| fail -> Upper |Idle|
|Send(body) | |  &lt;unreachble, error&gt;  |-|

### Finished
State:
- \- 


|Event|Cond|Action|Next|
|-----|----|------|----|
| - | - | - | - |



## Auth-Layer

> EAP peer and authenticator layers.  Based on the Code field, the EAP layer demultiplexes incoming EAP packets to the EAP peer and authenticator layers.  Typically, an EAP implementation on a given host will support either peer or authenticator functionality, but it is possible for a host to act as both an EAP peer and authenticator.  In such an implementation both EAP peer and authenticator layers will be present.
-- 2.2.  EAP Multiplexing Model, RFC 3748


### Default

State:
- current_method: Method
- allowed_methods: List[Method]

|Event|Cond|Action|Next|
|------|----|------|----|
| Fail |-   | - |  Failed |
| recv(body)| valid && body.meth == current_method | body -> UPPER | - |
| recv(body)| valid && body.meth == NAK && body[..] in allowed_methods| current_method = body[..] | - |
| recv(body)| else |  - | - |
| Next Meth | - | current_method = next(allowed_methods) | - |
| Success | - | send(type=success,body='') -> LOWER | Finished |

### Finished

State:
- shared_secret: Optional(bytes)


|Event|Cond|Action|Next|
|-----|----|------|----|
| - | - | - | - |

### Failed

State:
- \-

|Event|Cond|Action|Next|
|-----|----|------|----|
| - | - | - | - |



## Method-Layer

In-Events:
Start (Auth only)
Recv(body)

Out-Events:
Send(body, type)
Fail
NextMeth


# Peer 

## EAP-Layer

Same as Authenticator

## Peer-Layer


### Default

State:
- current_method: Method
- allowed_methods: List[Method]

|Event|Cond|Action|Next|
|------|----|------|----|
| Fail |-   | - |  Failed |
| recv(body) | body.type == success | get_shared_secret(current_method) | Finished |
| recv(body)| valid && body.meth == current_method | body -> UPPER | - |
| recv(body)| valid && body.meth in allowed_methods| current_method = body.meth <br/> body -> UPPER | - |
| recv(body)| valid && body.meth not in allowed_methods| send(body=[NAK, ..allowed_methods]) | - |
| recv(body)| else |  - | - |

### Finished

State:
- shared_secret: Optional(bytes)


|Event|Cond|Action|Next|
|-----|----|------|----|
| - | - | - | - |

### Failed

State:
- \-

|Event|Cond|Action|Next|
|-----|----|------|----|
| - | - | - | - |


-------


# Konfiguration

### EAP-Layer
- Retransmission-Timeout
- Max. Retransmissions

### Auth-Layer / Peer-Layer
- erlaubte Methoden, priotisiert

### Method-Layer
- MTU
- Identity
- Secrets
    - PSK (per User bei Auth)
    - TLS


