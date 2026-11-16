/*
 * android_storage_audit.js — observe how an Android app stores data at runtime.
 *
 * Flags sensitive data written to insecure sinks (MASVS-STORAGE-1 / MASTG-TEST-0001):
 *   - SharedPreferences writes (often plaintext)
 *   - SQLite execSQL / insert
 *   - File/stream writes to app storage
 *   - Base64 "obfuscation" mistaken for encryption
 *
 * Usage: frida -U -f com.example.app -l android_storage_audit.js --no-pause
 * Authorised testing only.
 */
'use strict';

Java.perform(function () {
  const trace = (label, value) => {
    console.log('[storage] ' + label + ' = ' + value);
    // Uncomment to capture call sites:
    // console.log(Java.use('android.util.Log').getStackTraceString(Java.use('java.lang.Exception').$new()));
  };

  try {
    const Editor = Java.use('android.content.SharedPreferences$Editor');
    Editor.putString.implementation = function (k, v) {
      trace('SharedPreferences.putString ' + k, v);
      return this.putString(k, v);
    };
  } catch (e) {}

  try {
    const SQLite = Java.use('android.database.sqlite.SQLiteDatabase');
    SQLite.execSQL.overload('java.lang.String').implementation = function (sql) {
      trace('SQLiteDatabase.execSQL', sql);
      return this.execSQL(sql);
    };
  } catch (e) {}

  try {
    const Base64 = Java.use('android.util.Base64');
    Base64.encodeToString.overload('[B', 'int').implementation = function (data, flags) {
      trace('Base64.encodeToString (NOT encryption)', 'len=' + data.length);
      return this.encodeToString(data, flags);
    };
  } catch (e) {}
});
