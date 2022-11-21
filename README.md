<h1 align="center">
RSA Signature Verify 🔑
</h1>

## Summary
- [Set Up](#set-up-)
- [Verify the signature](#verify-the-signature-)

## Set up 📦

### Create and enable a virtual environment

```
    $ pip install virtualenv
    $ python -m venv venv
    $ source venv/bin/activate
```

### Install the dependencies

```
    $ pip install -r requirements.txt
```

## Verify the signature ✅
For verifying the signature on text_signat.bin and text_signat2.bin execute:
```
    $ python main.py
```

The implementation needed by text_signat.bin (which was generated using the command rsautl on the openssl cli), uses some private methods from the implementation of the cryptography library. This methods can change overtime and the library doesn't guarantee that will exist on newer versions.
