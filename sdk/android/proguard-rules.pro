# Module ProGuard/R8 rules (applied to this library's own build, if minified).
-keepclasseswithmembernames,includedescriptorclasses class io.kseal.sdk.internal.NativeBridge {
    native <methods>;
}
