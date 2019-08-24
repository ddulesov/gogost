# Changelog

## 4.0:
    * Backward incompatible change: all keys passing to encryption
      functions are slices now, not the fixed arrays. That heavily
      simplifies the library usage
    * Fix bug with overwriting IVs memory in gost28147.CFB*crypter
    * TLSTREE, used in TLS 1.[23], implementation
    * gost3410.KEK2012* can be used with any curves, not only 512-bit ones
    * gost3410.PrivateKey satisfies crypto.Signer interface
    * gost34112012* hashes satisfy encoding.Binary(Un)Marshaler
    * Streebog256 HKDF test vectors

## 3.0:
    * Multilinear Galois Mode (MGM) block cipher mode for
      64 and 128 bit ciphers
    * KDF_GOSTR3411_2012_256 KDF
    * 34.12-2015 64-bit block cipher Магма (Magma)
    * Additional EAC 28147-89 Sbox
    * 34.10-2012 TC26 twisted Edwards curve related parameters
    * Coordinates conversion from twisted Edwards to Weierstrass
      form and vice versa
    * Fixed gost3410.PrivateKey's length validation
    * Backward incompatible change: gost3410.NewCurve takes big.Int,
      instead of encoded integers
    * Backward incompatible Sbox and curves parameters renaming, to
      comply with OIDs identifying them:

      Gost2814789_TestParamSet       -> SboxIdGost2814789TestParamSet
      Gost28147_CryptoProParamSetA   -> SboxIdGost2814789CryptoProAParamSet
      Gost28147_CryptoProParamSetB   -> SboxIdGost2814789CryptoProBParamSet
      Gost28147_CryptoProParamSetC   -> SboxIdGost2814789CryptoProCParamSet
      Gost28147_CryptoProParamSetD   -> SboxIdGost2814789CryptoProDParamSet
      GostR3411_94_TestParamSet      -> SboxIdGostR341194TestParamSet
      Gost28147_tc26_ParamZ          -> SboxIdtc26gost28147paramZ
      GostR3411_94_CryptoProParamSet -> SboxIdGostR341194CryptoProParamSet
      EACParamSet                    -> SboxEACParamSet

      CurveParamsGostR34102001cc            -> CurveGostR34102001ParamSetcc
      CurveParamsGostR34102001Test          -> CurveIdGostR34102001TestParamSet
      CurveParamsGostR34102001CryptoProA    -> CurveIdGostR34102001CryptoProAParamSet
      CurveParamsGostR34102001CryptoProB    -> CurveIdGostR34102001CryptoProBParamSet
      CurveParamsGostR34102001CryptoProC    -> CurveIdGostR34102001CryptoProCParamSet
      CurveParamsGostR34102001CryptoProXchA -> CurveIdGostR34102001CryptoProXchAParamSet
      CurveParamsGostR34102001CryptoProXchB -> CurveIdGostR34102001CryptoProXchBParamSet
      CurveParamsGostR34102012TC26ParamSetA -> CurveIdtc26gost341012512paramSetA
      CurveParamsGostR34102012TC26ParamSetB -> CurveIdtc26gost341012512paramSetB

    * Various additional test vectors
    * go modules friendliness

## 2.0:
    * 34.11-2012 is split on two different modules: gost34112012256 and
      gost34112012512
    * 34.11-94's digest is reversed. Now it is compatible with TC26's
      HMAC and PBKDF2 test vectors
    * gogost-streebog is split to streebog256 and streebog512
      correspondingly by analogy with sha* utilities
    * added VKO 34.10-2012 support with corresponding test vectors
    * gost3410.DigestSizeX is renamed to gost3410.ModeX because it is
      not related to digest size, but parameters and key sizes
    * KEK functions take big.Int UKM value. Use NewUKM to unmarshal
      raw binary UKM

## 1.1:
    * gogost-streebog is able to use either 256 or 512 bits digest size
    * 34.13-2015 padding methods
    * 28147-89 CBC mode of operation

## 1.0:
    Initial release.
