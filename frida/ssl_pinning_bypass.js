/*
 * ssl_pinning_bypass.js — dynamic test harness for TLS pinning.
 *
 * Purpose: during an AUTHORISED assessment, confirm whether an app's certificate
 * pinning can be defeated (MASVS-NETWORK-2 / MASTG-TEST-0022). If these hooks let
 * traffic flow to an intercepting proxy, pinning is not enforced correctly.
 *
 * Usage:  frida -U -f com.example.app -l ssl_pinning_bypass.js --no-pause
 * Covers: Android OkHttp CertificatePinner + TrustManager, and iOS NSURLSession.
 *
 * For use only on apps you are authorised to test.
 */
'use strict';

if (Java.available) {
  Java.perform(function () {
    // OkHttp CertificatePinner.check() -> no-op
    try {
      const CertificatePinner = Java.use('okhttp3.CertificatePinner');
      CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function () {
        console.log('[pinning] OkHttp CertificatePinner.check() bypassed');
        return;
      };
    } catch (e) { /* OkHttp not present */ }

    // Custom X509TrustManager -> accept all
    try {
      const X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
      const SSLContext = Java.use('javax.net.ssl.SSLContext');
      const TrustManager = Java.registerClass({
        name: 'org.mast.TrustAll',
        implements: [X509TrustManager],
        methods: {
          checkClientTrusted: function () {},
          checkServerTrusted: function () {},
          getAcceptedIssuers: function () { return []; },
        },
      });
      const init = SSLContext.init.overload(
        '[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom');
      init.implementation = function (km, tm, sr) {
        console.log('[pinning] SSLContext.init() -> injecting permissive TrustManager');
        init.call(this, km, [TrustManager.$new()], sr);
      };
    } catch (e) { console.log('[pinning] TrustManager hook failed: ' + e); }
  });
}

if (ObjC.available) {
  // iOS: defeat SecTrustEvaluate-based pinning by forcing a proceed result.
  try {
    const SecTrustEvaluate = new NativeFunction(
      Module.findExportByName('Security', 'SecTrustEvaluate'),
      'int', ['pointer', 'pointer']);
    Interceptor.replace(SecTrustEvaluate.address || Module.findExportByName('Security', 'SecTrustEvaluate'),
      new NativeCallback(function (trust, result) {
        if (!result.isNull()) { result.writeU32(1); } // kSecTrustResultProceed
        console.log('[pinning] iOS SecTrustEvaluate forced to proceed');
        return 0;
      }, 'int', ['pointer', 'pointer']));
  } catch (e) { console.log('[pinning] iOS hook failed: ' + e); }
}
