/*
 * JNI bridge for the kseal Rust trust core.
 *
 * Each Java_io_kseal_sdk_internal_NativeBridge_* function maps a Kotlin
 * `external` method (see NativeBridge.kt) onto a `kseal_*` C ABI export
 * (kseal.h). The same source is compiled by the NDK into libkseal_jni.so for
 * the device and by the host JDK for JVM unit tests, so the binding is
 * exercised against the real core on both.
 *
 * Memory discipline: every KsealBuffer produced by the core is copied into a
 * Java byte[] and then released with kseal_buffer_free — no leaks, no buffers
 * handed across the JVM boundary.
 */
#include <jni.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "kseal.h"

static inline KsealCoreHandle *as_handle(jlong h) {
    return (KsealCoreHandle *)(intptr_t)h;
}

/* Copies a Rust-owned KsealBuffer into a fresh Java byte[] and frees it.
 *
 * Callers invoke this only after the core returned an Ok status, so an empty
 * buffer here is a valid empty result (not an error) and is returned as a
 * zero-length array. NULL is reserved for a genuine JVM allocation failure, so
 * the Kotlin side can keep treating null strictly as an error. */
static jbyteArray buffer_to_jbytes(JNIEnv *env, KsealBuffer buf) {
    jbyteArray out = (*env)->NewByteArray(env, (jsize)buf.len);
    if (out != NULL && buf.len > 0 && buf.data != NULL) {
        (*env)->SetByteArrayRegion(env, out, 0, (jsize)buf.len, (const jbyte *)buf.data);
    }
    kseal_buffer_free(buf);
    return out;
}

JNIEXPORT jstring JNICALL
Java_io_kseal_sdk_internal_NativeBridge_nativeVersion(JNIEnv *env, jobject thiz) {
    (void)thiz;
    const char *v = kseal_version();
    return (*env)->NewStringUTF(env, v != NULL ? v : "");
}

JNIEXPORT jlong JNICALL
Java_io_kseal_sdk_internal_NativeBridge_nativeCoreNew(
    JNIEnv *env, jobject thiz,
    jbyteArray config_public_key, jbyteArray proof_key,
    jint platform, jint max_batch_events, jint risk_window, jint zstd_level) {
    (void)thiz;

    jsize pk_len = config_public_key ? (*env)->GetArrayLength(env, config_public_key) : 0;
    jsize proof_len = proof_key ? (*env)->GetArrayLength(env, proof_key) : 0;

    jbyte *pk = pk_len ? (*env)->GetByteArrayElements(env, config_public_key, NULL) : NULL;
    jbyte *proof = proof_len ? (*env)->GetByteArrayElements(env, proof_key, NULL) : NULL;

    KsealCoreHandle *handle = kseal_core_new(
        (const uint8_t *)pk, (uintptr_t)pk_len,
        (const uint8_t *)proof, (uintptr_t)proof_len,
        (int32_t)platform,
        (uintptr_t)(max_batch_events < 0 ? 0 : max_batch_events),
        (uintptr_t)(risk_window < 0 ? 0 : risk_window),
        (int32_t)zstd_level);

    if (pk) (*env)->ReleaseByteArrayElements(env, config_public_key, pk, JNI_ABORT);
    if (proof) (*env)->ReleaseByteArrayElements(env, proof_key, proof, JNI_ABORT);

    return (jlong)(intptr_t)handle;
}

JNIEXPORT void JNICALL
Java_io_kseal_sdk_internal_NativeBridge_nativeCoreFree(JNIEnv *env, jobject thiz, jlong handle) {
    (void)env;
    (void)thiz;
    kseal_core_free(as_handle(handle));
}

JNIEXPORT jint JNICALL
Java_io_kseal_sdk_internal_NativeBridge_nativeLoadConfig(
    JNIEnv *env, jobject thiz, jlong handle, jbyteArray bytes) {
    (void)thiz;
    jsize len = bytes ? (*env)->GetArrayLength(env, bytes) : 0;
    jbyte *data = len ? (*env)->GetByteArrayElements(env, bytes, NULL) : NULL;
    KsealStatus st = kseal_load_config(as_handle(handle), (const uint8_t *)data, (uintptr_t)len);
    if (data) (*env)->ReleaseByteArrayElements(env, bytes, data, JNI_ABORT);
    return (jint)st;
}

JNIEXPORT jlongArray JNICALL
Java_io_kseal_sdk_internal_NativeBridge_nativeEvaluateRisk(
    JNIEnv *env, jobject thiz, jlong handle, jlong risk_bits) {
    (void)thiz;
    uint32_t score = 0;
    int32_t confidence = 0;
    KsealStatus st = kseal_evaluate_risk(as_handle(handle), (uint64_t)risk_bits, &score, &confidence);
    if (st != 0) {
        return NULL;
    }
    jlongArray out = (*env)->NewLongArray(env, 2);
    if (out == NULL) return NULL;
    /* Widen the u32 score into a jlong so the full unsigned range survives the
     * boundary; a jint would wrap saturating scores (up to u32::MAX) negative. */
    jlong vals[2] = {(jlong)score, (jlong)confidence};
    (*env)->SetLongArrayRegion(env, out, 0, 2, vals);
    return out;
}

JNIEXPORT jint JNICALL
Java_io_kseal_sdk_internal_NativeBridge_nativeComputeRiskLevel(
    JNIEnv *env, jobject thiz, jlong handle, jlong risk_bits) {
    (void)env;
    (void)thiz;
    return (jint)kseal_compute_risk_level(as_handle(handle), (uint64_t)risk_bits);
}

JNIEXPORT jbyteArray JNICALL
Java_io_kseal_sdk_internal_NativeBridge_nativeCreateEvent(
    JNIEnv *env, jobject thiz, jlong handle,
    jint event_type, jlong risk_bits, jint confidence,
    jstring build_hash, jstring policy_hash, jstring install_key_hash,
    jlong coarse_time_bucket, jstring country) {
    (void)thiz;

    const char *build = build_hash ? (*env)->GetStringUTFChars(env, build_hash, NULL) : NULL;
    const char *policy = policy_hash ? (*env)->GetStringUTFChars(env, policy_hash, NULL) : NULL;
    const char *install = install_key_hash ? (*env)->GetStringUTFChars(env, install_key_hash, NULL) : NULL;
    const char *country_c = country ? (*env)->GetStringUTFChars(env, country, NULL) : NULL;

    KsealBuffer out = {0};
    KsealStatus st = kseal_create_event(
        as_handle(handle),
        (int32_t)event_type,
        (uint64_t)risk_bits,
        (int32_t)confidence,
        build, policy, install,
        (int64_t)coarse_time_bucket,
        country_c,
        &out);

    if (build) (*env)->ReleaseStringUTFChars(env, build_hash, build);
    if (policy) (*env)->ReleaseStringUTFChars(env, policy_hash, policy);
    if (install) (*env)->ReleaseStringUTFChars(env, install_key_hash, install);
    if (country_c) (*env)->ReleaseStringUTFChars(env, country, country_c);

    if (st != 0) {
        kseal_buffer_free(out);
        return NULL;
    }
    return buffer_to_jbytes(env, out);
}

JNIEXPORT jbyteArray JNICALL
Java_io_kseal_sdk_internal_NativeBridge_nativeBatchAndCompress(
    JNIEnv *env, jobject thiz, jlong handle, jobjectArray events) {
    (void)thiz;

    jsize count = events ? (*env)->GetArrayLength(env, events) : 0;

    KsealBytesView *views = NULL;
    jbyteArray *locals = NULL;
    jbyte **ptrs = NULL;
    if (count > 0) {
        views = (KsealBytesView *)calloc((size_t)count, sizeof(KsealBytesView));
        locals = (jbyteArray *)calloc((size_t)count, sizeof(jbyteArray));
        ptrs = (jbyte **)calloc((size_t)count, sizeof(jbyte *));
        if (views == NULL || locals == NULL || ptrs == NULL) {
            free(views);
            free(locals);
            free(ptrs);
            return NULL;
        }
        for (jsize i = 0; i < count; i++) {
            jbyteArray ev = (jbyteArray)(*env)->GetObjectArrayElement(env, events, i);
            locals[i] = ev;
            jsize len = ev ? (*env)->GetArrayLength(env, ev) : 0;
            jbyte *p = (ev && len) ? (*env)->GetByteArrayElements(env, ev, NULL) : NULL;
            ptrs[i] = p;
            views[i].data = (const uint8_t *)p;
            views[i].len = (uintptr_t)len;
        }
    }

    KsealBuffer out = {0};
    KsealStatus st = kseal_batch_and_compress(as_handle(handle), views, (uintptr_t)count, &out);

    if (count > 0) {
        for (jsize i = 0; i < count; i++) {
            if (ptrs[i]) (*env)->ReleaseByteArrayElements(env, locals[i], ptrs[i], JNI_ABORT);
            if (locals[i]) (*env)->DeleteLocalRef(env, locals[i]);
        }
        free(views);
        free(locals);
        free(ptrs);
    }

    if (st != 0) {
        kseal_buffer_free(out);
        return NULL;
    }
    return buffer_to_jbytes(env, out);
}

JNIEXPORT jbyteArray JNICALL
Java_io_kseal_sdk_internal_NativeBridge_nativeGenerateRequestProof(
    JNIEnv *env, jobject thiz, jlong handle,
    jstring token_id, jbyteArray request_hash, jbyteArray nonce, jlong seq) {
    (void)thiz;

    const char *token = token_id ? (*env)->GetStringUTFChars(env, token_id, NULL) : NULL;
    jsize rh_len = request_hash ? (*env)->GetArrayLength(env, request_hash) : 0;
    jsize nc_len = nonce ? (*env)->GetArrayLength(env, nonce) : 0;
    jbyte *rh = rh_len ? (*env)->GetByteArrayElements(env, request_hash, NULL) : NULL;
    jbyte *nc = nc_len ? (*env)->GetByteArrayElements(env, nonce, NULL) : NULL;

    KsealBuffer out = {0};
    KsealStatus st = kseal_generate_request_proof(
        as_handle(handle),
        token,
        (const uint8_t *)rh, (uintptr_t)rh_len,
        (const uint8_t *)nc, (uintptr_t)nc_len,
        (int64_t)seq,
        &out);

    if (token) (*env)->ReleaseStringUTFChars(env, token_id, token);
    if (rh) (*env)->ReleaseByteArrayElements(env, request_hash, rh, JNI_ABORT);
    if (nc) (*env)->ReleaseByteArrayElements(env, nonce, nc, JNI_ABORT);

    if (st != 0) {
        kseal_buffer_free(out);
        return NULL;
    }
    return buffer_to_jbytes(env, out);
}

JNIEXPORT jint JNICALL
Java_io_kseal_sdk_internal_NativeBridge_nativeVerifyConfigSignature(
    JNIEnv *env, jobject thiz, jbyteArray config, jbyteArray signature, jbyteArray public_key) {
    (void)thiz;

    jsize cfg_len = config ? (*env)->GetArrayLength(env, config) : 0;
    jsize sig_len = signature ? (*env)->GetArrayLength(env, signature) : 0;
    jsize pk_len = public_key ? (*env)->GetArrayLength(env, public_key) : 0;
    jbyte *cfg = cfg_len ? (*env)->GetByteArrayElements(env, config, NULL) : NULL;
    jbyte *sig = sig_len ? (*env)->GetByteArrayElements(env, signature, NULL) : NULL;
    jbyte *pk = pk_len ? (*env)->GetByteArrayElements(env, public_key, NULL) : NULL;

    int32_t result = kseal_verify_config_signature(
        (const uint8_t *)cfg, (uintptr_t)cfg_len,
        (const uint8_t *)sig, (uintptr_t)sig_len,
        (const uint8_t *)pk, (uintptr_t)pk_len);

    if (cfg) (*env)->ReleaseByteArrayElements(env, config, cfg, JNI_ABORT);
    if (sig) (*env)->ReleaseByteArrayElements(env, signature, sig, JNI_ABORT);
    if (pk) (*env)->ReleaseByteArrayElements(env, public_key, pk, JNI_ABORT);

    return (jint)result;
}

JNIEXPORT jbyteArray JNICALL
Java_io_kseal_sdk_internal_NativeBridge_nativeCompress(
    JNIEnv *env, jobject thiz, jbyteArray data, jint level) {
    (void)thiz;
    jsize len = data ? (*env)->GetArrayLength(env, data) : 0;
    jbyte *p = len ? (*env)->GetByteArrayElements(env, data, NULL) : NULL;
    KsealBuffer out = {0};
    KsealStatus st = kseal_compress((const uint8_t *)p, (uintptr_t)len, (int32_t)level, &out);
    if (p) (*env)->ReleaseByteArrayElements(env, data, p, JNI_ABORT);
    if (st != 0) {
        kseal_buffer_free(out);
        return NULL;
    }
    return buffer_to_jbytes(env, out);
}

JNIEXPORT jbyteArray JNICALL
Java_io_kseal_sdk_internal_NativeBridge_nativeDecompress(
    JNIEnv *env, jobject thiz, jbyteArray data) {
    (void)thiz;
    jsize len = data ? (*env)->GetArrayLength(env, data) : 0;
    jbyte *p = len ? (*env)->GetByteArrayElements(env, data, NULL) : NULL;
    KsealBuffer out = {0};
    KsealStatus st = kseal_decompress((const uint8_t *)p, (uintptr_t)len, &out);
    if (p) (*env)->ReleaseByteArrayElements(env, data, p, JNI_ABORT);
    if (st != 0) {
        kseal_buffer_free(out);
        return NULL;
    }
    return buffer_to_jbytes(env, out);
}

JNIEXPORT jbyteArray JNICALL
Java_io_kseal_sdk_internal_NativeBridge_nativeGenerateNonce(
    JNIEnv *env, jobject thiz, jint len) {
    (void)thiz;
    KsealBuffer out = {0};
    KsealStatus st = kseal_generate_nonce((uintptr_t)(len < 0 ? 0 : len), &out);
    if (st != 0) {
        kseal_buffer_free(out);
        return NULL;
    }
    return buffer_to_jbytes(env, out);
}

JNIEXPORT jlong JNICALL
Java_io_kseal_sdk_internal_NativeBridge_nativeReattestIntervalSecs(
    JNIEnv *env, jobject thiz, jlong handle) {
    (void)env;
    (void)thiz;
    return (jlong)kseal_reattest_interval_secs(as_handle(handle));
}

JNIEXPORT jint JNICALL
Java_io_kseal_sdk_internal_NativeBridge_nativeDecision(
    JNIEnv *env, jobject thiz, jlong handle, jlong risk_bits) {
    (void)env;
    (void)thiz;
    return (jint)kseal_decision(as_handle(handle), (uint64_t)risk_bits);
}

JNIEXPORT jintArray JNICALL
Java_io_kseal_sdk_internal_NativeBridge_nativeDecisionWithLevel(
    JNIEnv *env, jobject thiz, jlong handle, jlong risk_bits) {
    (void)thiz;
    int32_t level = 0;
    int32_t decision = 0;
    KsealStatus st = kseal_decision_with_level(
        as_handle(handle), (uint64_t)risk_bits, &level, &decision);
    if (st != 0) {
        return NULL;
    }
    jintArray out = (*env)->NewIntArray(env, 2);
    if (out == NULL) return NULL;
    jint vals[2] = {(jint)level, (jint)decision};
    (*env)->SetIntArrayRegion(env, out, 0, 2, vals);
    return out;
}

JNIEXPORT jint JNICALL
Java_io_kseal_sdk_internal_NativeBridge_nativeApplyKillSwitch(
    JNIEnv *env, jobject thiz, jlong handle, jbyteArray bytes) {
    (void)thiz;
    jsize len = bytes ? (*env)->GetArrayLength(env, bytes) : 0;
    jbyte *data = len ? (*env)->GetByteArrayElements(env, bytes, NULL) : NULL;
    int32_t result = kseal_apply_kill_switch(as_handle(handle), (const uint8_t *)data, (uintptr_t)len);
    if (data) (*env)->ReleaseByteArrayElements(env, bytes, data, JNI_ABORT);
    return (jint)result;
}

/* Native anti-debug / anti-Frida probes (no handle: they inspect the current
 * process). Return 1 (present), 0 (clean), or -1 (unavailable); the Kotlin
 * detectors raise a signal only on a strict `== 1` so an unavailable check
 * contributes nothing. */
JNIEXPORT jint JNICALL
Java_io_kseal_sdk_internal_NativeBridge_nativeDebuggerPresent(JNIEnv *env, jobject thiz) {
    (void)env;
    (void)thiz;
    return (jint)kseal_native_debugger_present();
}

JNIEXPORT jint JNICALL
Java_io_kseal_sdk_internal_NativeBridge_nativeHookPresent(JNIEnv *env, jobject thiz) {
    (void)env;
    (void)thiz;
    return (jint)kseal_native_hook_present();
}

JNIEXPORT jint JNICALL
Java_io_kseal_sdk_internal_NativeBridge_nativeIsKilled(
    JNIEnv *env, jobject thiz, jlong handle) {
    (void)env;
    (void)thiz;
    return (jint)kseal_is_killed(as_handle(handle));
}
