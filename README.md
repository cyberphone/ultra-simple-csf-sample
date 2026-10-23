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

Expected output:
```code
First argument: data
Second argument: more data
Signed data: a301646461746102696d6f72652064617461f863a10105
Algorithm: 5
Signature value: 237e674c7be1818ddd7eaacf40ca80415b9ad816880751d2136c45385207420c

Sample validated!!!
```
