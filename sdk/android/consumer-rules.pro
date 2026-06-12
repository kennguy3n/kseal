# Keep the JNI entry points reachable; their names are resolved by the native
# bridge via the standard JNI mangling and must not be renamed/removed.
-keepclasseswithmembernames,includedescriptorclasses class io.kseal.sdk.internal.NativeBridge {
    native <methods>;
}
-keep class io.kseal.sdk.internal.NativeBridge { *; }

# Public SDK surface.
-keep class io.kseal.sdk.KsealSDK { public *; }
-keep class io.kseal.sdk.RiskAssessment { *; }
-keep class io.kseal.sdk.RequestProof { *; }
-keep enum io.kseal.sdk.RiskSignal { *; }
-keep enum io.kseal.sdk.TrustLevel { *; }
