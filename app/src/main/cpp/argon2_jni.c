// JNI wrapper for the Argon2 reference implementation: the KDF memory (up to 1 GiB for cryptsetup defaults)
// lives in native memory, outside the Java heap limit, and lanes run on threads.
#include <jni.h>
#include <string.h>
#include "argon2.h"

JNIEXPORT jint JNICALL
Java_me_nocke_cryptic_vaults_luks_NativeArgon2_hash(JNIEnv *env, jclass cls, jint type, jint t_cost, jint m_cost_kib,
                                             jint lanes, jbyteArray pass, jbyteArray salt, jbyteArray out) {
    jsize pass_len = (*env)->GetArrayLength(env, pass);
    jsize salt_len = (*env)->GetArrayLength(env, salt);
    jsize out_len = (*env)->GetArrayLength(env, out);
    jbyte *p = (*env)->GetByteArrayElements(env, pass, NULL);
    jbyte *s = (*env)->GetByteArrayElements(env, salt, NULL);
    jbyte *o = (*env)->GetByteArrayElements(env, out, NULL);
    int rc = argon2_hash((uint32_t) t_cost, (uint32_t) m_cost_kib, (uint32_t) lanes, p, (size_t) pass_len, s,
                         (size_t) salt_len, o, (size_t) out_len, NULL, 0,
                         type == 2 ? Argon2_id : Argon2_i, ARGON2_VERSION_13);
    memset(p, 0, (size_t) pass_len);
    (*env)->ReleaseByteArrayElements(env, pass, p, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, salt, s, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, out, o, rc == ARGON2_OK ? 0 : JNI_ABORT);
    return rc;
}
