## Ultra-simple and ultra-primitive CSF sample

Sample:
```cbor
{
  1: "data",
  2: "more data",
  simple(99): {
    1: 5,
    6: h'237e674c7be1818ddd7eaacf40ca80415b9ad816880751d2136c45385207420c'
  }
}
```

Secret key:
```code
7fdd851a3b9d2dafc5f0d00030e22b9343900cd42ede4948568a4a2ee655291a
```

Expected output:
```code
First argument: data
Second argument: more data
Signed data: a301646461746102696d6f72652064617461f863a10105
Algorithm: 5 (COSE HS256)
Signature value: 237e674c7be1818ddd7eaacf40ca80415b9ad816880751d2136c45385207420c

Sample validated!!!
```
## Notes
In spite of its relative simplicity, the decoder checks that a CBOR object:
- has exactly the expected elements and associated types
- adheres to deterministic encoding

The decoder is supposed to withstand incorrectly formatted objects, without causing buffer overrun conditions.

The decoder does not depend on `malloc()` or deeply nested function-calls.

The sample shows that deterministically encoded CBOR can (at the expense of the developer), be dealt with by programmatically honoring the order of map elements.
