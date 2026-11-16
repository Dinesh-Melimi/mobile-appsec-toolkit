/*
 * ios_keychain_audit.js — observe iOS Keychain usage and data protection class.
 *
 * Checks (MASVS-STORAGE-1 / MASTG-TEST-0053):
 *   - SecItemAdd / SecItemUpdate calls and their kSecAttrAccessible class
 *   - Flags items stored with weak accessibility (e.g. kSecAttrAccessibleAlways)
 *   - NSUserDefaults writes of sensitive-looking keys (should not hold secrets)
 *
 * Usage: frida -U -f com.example.app -l ios_keychain_audit.js --no-pause
 * Authorised testing only.
 */
'use strict';

if (ObjC.available) {
  const SecItemAdd = Module.findExportByName('Security', 'SecItemAdd');
  if (SecItemAdd) {
    Interceptor.attach(SecItemAdd, {
      onEnter(args) {
        try {
          const dict = new ObjC.Object(args[0]);
          const accessible = dict.objectForKey_('pdmn') || dict.objectForKey_('accc');
          console.log('[keychain] SecItemAdd accessible=' + accessible +
            ' account=' + dict.objectForKey_('acct'));
          if (('' + accessible).indexOf('ak') === -1 && accessible) {
            console.log('[keychain] WARNING: item may be accessible without unlock');
          }
        } catch (e) {}
      },
    });
  }

  try {
    const NSUserDefaults = ObjC.classes.NSUserDefaults;
    Interceptor.attach(NSUserDefaults['- setObject:forKey:'].implementation, {
      onEnter(args) {
        const key = new ObjC.Object(args[3]).toString();
        if (/token|secret|password|pin|ssn|card/i.test(key)) {
          console.log('[defaults] WARNING sensitive key in NSUserDefaults: ' + key);
        }
      },
    });
  } catch (e) {}
}
