(self["webpackChunkgame"] = self["webpackChunkgame"] || []).push([
  [4328],
  {
    18349: function (c, l, Z) {
      var a;
      ((c = Z.nmd(c)),
        Z(16280),
        Z(27495),
        Z(25440),
        (function () {
          var d = l,
            m = (c && c.exports, "object" == typeof Z.g && Z.g);
          m.global !== m && m.window;
          var t = function (c) {
            this.message = c;
          };
          ((t.prototype = new Error()),
            (t.prototype.name = "InvalidCharacterError"));
          var n = function (c) {
              throw new t(c);
            },
            V =
              "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
            Y = /[\t\n\f\r ]/g,
            G = function (c) {
              c = String(c).replace(Y, "");
              var l = c.length;
              (l % 4 == 0 && ((c = c.replace(/==?$/, "")), (l = c.length)),
                (l % 4 == 1 || /[^+a-zA-Z0-9/]/.test(c)) &&
                  n(
                    "Invalid character: the string to be decoded is not correctly encoded.",
                  ));
              var Z,
                a,
                d = 0,
                m = "",
                t = -1;
              while (++t < l)
                ((a = V.indexOf(c.charAt(t))),
                  (Z = d % 4 ? 64 * Z + a : a),
                  d++ % 4 &&
                    (m += String.fromCharCode(255 & (Z >> ((-2 * d) & 6)))));
              return m;
            },
            e = function (c) {
              ((c = String(c)),
                /[^\0-\xFF]/.test(c) &&
                  n(
                    "The string to be encoded contains characters outside of the Latin1 range.",
                  ));
              var l,
                Z,
                a,
                d,
                m = c.length % 3,
                t = "",
                Y = -1,
                G = c.length - m;
              while (++Y < G)
                ((l = c.charCodeAt(Y) << 16),
                  (Z = c.charCodeAt(++Y) << 8),
                  (a = c.charCodeAt(++Y)),
                  (d = l + Z + a),
                  (t +=
                    V.charAt((d >> 18) & 63) +
                    V.charAt((d >> 12) & 63) +
                    V.charAt((d >> 6) & 63) +
                    V.charAt(63 & d)));
              return (
                2 == m
                  ? ((l = c.charCodeAt(Y) << 8),
                    (Z = c.charCodeAt(++Y)),
                    (d = l + Z),
                    (t +=
                      V.charAt(d >> 10) +
                      V.charAt((d >> 4) & 63) +
                      V.charAt((d << 2) & 63) +
                      "="))
                  : 1 == m &&
                    ((d = c.charCodeAt(Y)),
                    (t += V.charAt(d >> 2) + V.charAt((d << 4) & 63) + "==")),
                t
              );
            },
            b = { encode: e, decode: G, version: "1.0.0" };
          ((a = function () {
            return b;
          }.call(l, Z, l, c)),
            void 0 === a || (c.exports = a));
        })());
    },
    24348: function (c, l, Z) {
      "use strict";
      Z.d(l, {
        zt: function () {
          return e;
        },
        DS: function () {
          return G;
        },
      });
      (Z(18111), Z(22489), Z(27495), Z(25440), Z(62953));
      const a = [
        "ZnVjaw==",
        "ZnVja2JhZ3M=",
        "Y29jaw==",
        "Y29ja2JhZ3M=",
        "Y3VudA==",
        "c2hpdA==",
        "Yml0Y2g=",
        "YXNz",
        "YXJzZQ==",
        "YmFzdGFyZA==",
        "Ym9sbG9ja3M=",
        "cG9v",
        "cG9vcA==",
        "YnVtcw==",
        "c2hpdGJhZw==",
        "ZGlja2JhZw==",
        "ZGljaw==",
        "d2Vl",
        "ZmFydA==",
        "YnV0dA==",
        "cmV0YXJk",
        "bmlnZ2Vy",
        "ZnV1Y2s=",
        "ZnV1dWNr",
        "YW5hbA==",
        "YW51cw==",
        "YXJzZQ==",
        "YXNzZnVja2Vy",
        "YXNzaG9sZQ==",
        "YXNzc2hvbGU=",
        "YmFzdGFyZA==",
        "Yml0Y2g=",
        "Ymxvb2R5",
        "Ym9vbmc=",
        "Y29ja2Z1Y2tlcg==",
        "Y29ja3N1Y2s=",
        "Y29ja3N1Y2tlcg==",
        "Y29vbg==",
        "Y29vbm5hc3M=",
        "Y3JhcA==",
        "Y3liZXJmdWNr",
        "ZGFtbg==",
        "ZGljaw==",
        "ZG91Y2hl",
        "ZXJlY3Rpb24=",
        "ZXJvdGlj",
        "ZmFn",
        "ZmFnZ290",
        "ZnVja2Fzcw==",
        "ZnVja2hvbGU=",
        "Z29vaw==",
        "aGFyZGNvcmU=",
        "aG9tb2Vyb3RpYw==",
        "aG9yZQ==",
        "bGVzYmlhbg==",
        "bGVzYmlhbnM=",
        "ZnVja2Vy",
        "bW90aGVyZnVjaw==",
        "bW90aGVyZnVja2Vy",
        "bmVncm8=",
        "bmlnZ2Vy",
        "b3JnYXNpbQ==",
        "b3JnYXNt",
        "cGVuaXM=",
        "cGVuaXNmdWNrZXI=",
        "cGlzcw==",
        "cG9ybg==",
        "cG9ybm8=",
        "cG9ybm9ncmFwaHk=",
        "cHVzc3k=",
        "cmV0YXJk",
        "c2FkaXN0",
        "c2V4",
        "c2V4eQ==",
        "c2x1dA==",
        "dGl0cw==",
        "dmlhZ3Jh",
        "d2hvcmU=",
        "eHh4",
        "YTU1",
        "YTU1aG9sZQ==",
        "YWVvbHVz",
        "YWhvbGU=",
        "YW5hbA==",
        "YW5hbHByb2Jl",
        "YW5pbGluZ3Vz",
        "YW51cw==",
        "YXJlb2xh",
        "YXJlb2xl",
        "YXJpYW4=",
        "YXJ5YW4=",
        "YXNzYmFuZw==",
        "YXNzYmFuZ2Vk",
        "YXNzYmFuZ3M=",
        "YXNzZXM=",
        "YXNzZnVjaw==",
        "YXNzZnVja2Vy",
        "YXNzaDBsZQ==",
        "YXNzaGF0",
        "YXNzaG8xZQ==",
        "YXNzaG9sZXM=",
        "YXNzbWFzdGVy",
        "YXNzbXVuY2g=",
        "YXNzd2lwZQ==",
        "YXNzd2lwZXM=",
        "YXphemVs",
        "YXp6",
        "YjF0Y2g=",
        "YmFsbHNhY2s=",
        "YmFyZg==",
        "YmFzdGFyZA==",
        "YmFzdGFyZHM=",
        "YmF3ZHk=",
        "YmVhbmVy",
        "YmVhcmRlZGNsYW0=",
        "YmVhc3RpYWxpdHk=",
        "YmVhdGNo",
        "YmVlcg==",
        "YmVleW90Y2g=",
        "YmVvdGNo",
        "YmlhdGNo",
        "YmlndGl0cw==",
        "YmlnIHRpdHM=",
        "YmltYm8=",
        "Yml0Y2g=",
        "Yml0Y2hlZA==",
        "Yml0Y2hlcw==",
        "Yml0Y2h5",
        "YmxvdyBqb2I=",
        "Ymxvd2pvYg==",
        "Ymxvd2pvYnM=",
        "Ym9k",
        "Ym9kaWx5",
        "Ym9pbms=",
        "Ym9sbG9jaw==",
        "Ym9sbG9ja3M=",
        "Ym9sbG9r",
        "Ym9uZWQ=",
        "Ym9uZXI=",
        "Ym9uZXJz",
        "Ym9uZw==",
        "Ym9vYg==",
        "Ym9vYmllcw==",
        "Ym9vYnM=",
        "Ym9vYnk=",
        "Ym9vZ2Vy",
        "Ym9va2ll",
        "Ym9vdGVl",
        "Ym9vdGll",
        "Ym9vdHk=",
        "Ym9vemU=",
        "Ym9vemVy",
        "Ym9venk=",
        "Ym9zb20=",
        "Ym9zb215",
        "Ym93ZWxz",
        "YnJh",
        "YnJhc3NpZXJl",
        "YnVnZ2Vy",
        "YnVra2FrZQ==",
        "YnVsbHNoaXQ=",
        "YnVsbCBzaGl0",
        "YnVsbHNoaXRz",
        "YnVsbHNoaXR0ZWQ=",
        "YnVsbHR1cmRz",
        "YnVzdHk=",
        "YnV0dA==",
        "YnV0dCBmdWNr",
        "YnV0dGZ1Y2s=",
        "YnV0dGZ1Y2tlcg==",
        "YnV0dGZ1Y2tlcg==",
        "YnV0dHBsdWc=",
        "Yy4wLmMuaw==",
        "Yy5vLmMuay4=",
        "Yy51Lm4udA==",
        "YzBjaw==",
        "Yy0wLWMtaw==",
        "Y2FjYQ==",
        "Y2Fob25l",
        "Y2FtZWx0b2U=",
        "Y2FycGV0bXVuY2hlcg==",
        "Y2F3aw==",
        "Y2Vydml4",
        "Y2hpbmM=",
        "Y2hpbmNz",
        "Y2hpbms=",
        "Y2hpbms=",
        "Y2hvZGU=",
        "Y2hvZGVz",
        "Y2wxdA==",
        "Y2xpdA==",
        "Y2xpdG9yaXM=",
        "Y2xpdG9ydXM=",
        "Y2xpdHM=",
        "Y2xpdHR5",
        "Y29jYWlu",
        "Y29jYWluZQ==",
        "Y29jaw==",
        "Yy1vLWMtaw==",
        "Y29ja2Jsb2Nr",
        "Y29ja2hvbHN0ZXI=",
        "Y29ja2tub2NrZXI=",
        "Y29ja3M=",
        "Y29ja3Ntb2tlcg==",
        "Y29ja3N1Y2tlcg==",
        "Y29jayBzdWNrZXI=",
        "Y29pdGFs",
        "Y29tbWll",
        "Y29vbg==",
        "Y29vbnM=",
        "Y29ya3N1Y2tlcg==",
        "Y3JhY2t3aG9yZQ==",
        "Y3JhcA==",
        "Y3JhcHB5",
        "Y3Vt",
        "Y3VtbWlu",
        "Y3VtbWluZw==",
        "Y3Vtc2hvdA==",
        "Y3Vtc2hvdHM=",
        "Y3Vtc2x1dA==",
        "Y3Vtc3RhaW4=",
        "Y3VuaWxpbmd1cw==",
        "Y3VubmlsaW5ndXM=",
        "Y3Vubnk=",
        "Y3VudA==",
        "Y3VudA==",
        "Yy11LW4tdA==",
        "Y3VudGZhY2U=",
        "Y3VudGh1bnRlcg==",
        "Y3VudGxpY2s=",
        "Y3VudGxpY2tlcg==",
        "Y3VudHM=",
        "ZDBuZw==",
        "ZDB1Y2gz",
        "ZDB1Y2hl",
        "ZDFjaw==",
        "ZDFsZDA=",
        "ZDFsZG8=",
        "ZGFnbw==",
        "ZGFnb3M=",
        "ZGFtbWl0",
        "ZGFtbg==",
        "ZGFtbmVk",
        "ZGFtbml0",
        "ZGF3Z2llLXN0eWxl",
        "ZGljaw==",
        "ZGlja2JhZw==",
        "ZGlja2RpcHBlcg==",
        "ZGlja2ZhY2U=",
        "ZGlja2ZsaXBwZXI=",
        "ZGlja2hlYWQ=",
        "ZGlja2hlYWRz",
        "ZGlja2lzaA==",
        "ZGljay1pc2g=",
        "ZGlja3JpcHBlcg==",
        "ZGlja3NpcHBlcg==",
        "ZGlja3dlZWQ=",
        "ZGlja3doaXBwZXI=",
        "ZGlja3ppcHBlcg==",
        "ZGlkZGxl",
        "ZGlrZQ==",
        "ZGlsZG8=",
        "ZGlsZG9z",
        "ZGlsaWdhZg==",
        "ZGlsbHdlZWQ=",
        "ZGltd2l0",
        "ZGluZ2xl",
        "ZGlwc2hpcA==",
        "ZG9nZ2llLXN0eWxl",
        "ZG9nZ3ktc3R5bGU=",
        "ZG9uZw==",
        "ZG9vZnVz",
        "ZG9vc2g=",
        "ZG9wZXk=",
        "ZG91Y2gz",
        "ZG91Y2hl",
        "ZG91Y2hlYmFn",
        "ZG91Y2hlYmFncw==",
        "ZG91Y2hleQ==",
        "ZHVtYXNz",
        "ZHVtYmFzcw==",
        "ZHVtYmFzc2Vz",
        "ZHVtbXk=",
        "ZHlrZQ==",
        "ZHlrZXM=",
        "ZWphY3VsYXRl",
        "ZXJlY3Q=",
        "ZXJlY3Rpb24=",
        "ZXJvdGlj",
        "ZXNzb2hiZWU=",
        "ZXh0YWN5",
        "ZXh0YXN5",
        "Zi51LmMuaw==",
        "ZmFjaw==",
        "ZmFn",
        "ZmFnZw==",
        "ZmFnZ2Vk",
        "ZmFnZ2l0",
        "ZmFnZ290",
        "ZmFnb3Q=",
        "ZmFncw==",
        "ZmFpZw==",
        "ZmFpZ3Q=",
        "ZmFubnliYW5kaXQ=",
        "ZmFydA==",
        "ZmFydGtub2NrZXI=",
        "ZmVsY2g=",
        "ZmVsY2hlcg==",
        "ZmVsY2hpbmc=",
        "ZmVsbGF0ZQ==",
        "ZmVsbGF0aW8=",
        "ZmVsdGNo",
        "ZmVsdGNoZXI=",
        "ZmlzdGVk",
        "ZmlzdGluZw==",
        "ZmlzdHk=",
        "Zmxvb3p5",
        "Zm9hZA==",
        "Zm9uZGxl",
        "Zm9vYmFy",
        "Zm9yZXNraW4=",
        "Zm9ydG5pdGU=",
        "ZnJlZXg=",
        "ZnJpZ2c=",
        "ZnJpZ2dh",
        "ZnViYXI=",
        "ZnVjaw==",
        "Zi11LWMtaw==",
        "ZnVja2Fzcw==",
        "ZnVja2Vk",
        "ZnVja2Vk",
        "ZnVja2Vy",
        "ZnVja2ZhY2U=",
        "ZnVja2lu",
        "ZnVja2luZw==",
        "ZnVja251Z2dldA==",
        "ZnVja251dA==",
        "ZnVja29mZg==",
        "ZnVja3M=",
        "ZnVja3RhcmQ=",
        "ZnVjay10YXJk",
        "ZnVja3Vw",
        "ZnVja3dhZA==",
        "ZnVja3dpdA==",
        "ZnVkZ2VwYWNrZXI=",
        "ZnVr",
        "ZnZjaw==",
        "Znhjaw==",
        "Z2Fl",
        "Z2Fp",
        "Z2FuamE=",
        "Z2F5",
        "Z2F5cw==",
        "Z2V5",
        "Z2Z5",
        "Z2hheQ==",
        "Z2hleQ==",
        "Z2lnb2xv",
        "Z2xhbnM=",
        "Z29hdHNl",
        "Z29kYW1u",
        "Z29kYW1uaXQ=",
        "Z29kZGFt",
        "Z29kZGFtbWl0",
        "Z29kZGFtbg==",
        "Z29sZGVuc2hvd2Vy",
        "Z29uYWQ=",
        "Z29uYWRz",
        "Z29vaw==",
        "Z29va3M=",
        "Z3Jpbmdv",
        "Z3Nwb3Q=",
        "Zy1zcG90",
        "Z3Rmbw==",
        "Z3VpZG8=",
        "aDBtMA==",
        "aDBtbw==",
        "aGFuZGpvYg==",
        "aGFyZCBvbg==",
        "aGUxMQ==",
        "aGViZQ==",
        "aGVlYg==",
        "aGVtcA==",
        "aGVyb2lu",
        "aGVycA==",
        "aGVycGVz",
        "aGVycHk=",
        "aGl2",
        "aG9iYWc=",
        "aG9tMA==",
        "aG9tZXk=",
        "aG9tbw==",
        "aG9tb2V5",
        "aG9ua3k=",
        "aG9vY2g=",
        "aG9va2Fo",
        "aG9va2Vy",
        "aG9vcg==",
        "aG9vdGNo",
        "aG9vdGVy",
        "aG9vdGVycw==",
        "aG9ybnk=",
        "aHVtcGVk",
        "aHVtcGluZw==",
        "aHVzc3k=",
        "aHltZW4=",
        "aW5icmVk",
        "aW5jZXN0",
        "aW5qdW4=",
        "ajNyazBmZg==",
        "amFja2Fzcw==",
        "amFja2hvbGU=",
        "amFja29mZg==",
        "amFw",
        "amFwcw==",
        "amVyazBmZg==",
        "amVya2Vk",
        "amVya29mZg==",
        "amlzbQ==",
        "aml6",
        "aml6bQ==",
        "aml6eg==",
        "aml6emVk",
        "anVua2ll",
        "anVua3k=",
        "a2lrZQ==",
        "a2lrZXM=",
        "a2lsbGVy",
        "a2lua3k=",
        "a2tr",
        "a2xhbg==",
        "a25vYmVuZA==",
        "a29vY2g=",
        "a29vY2hlcw==",
        "a29vdGNo",
        "a3JhdXQ=",
        "a3lrZQ==",
        "bGFiaWE=",
        "bGVjaA==",
        "bGVwZXI=",
        "bGVzYmlhbnM=",
        "bGVzYm8=",
        "bGVzYm9z",
        "bGV6",
        "bGV6Ymlhbg==",
        "bGV6YmlhbnM=",
        "bGV6Ym8=",
        "bGV6Ym9z",
        "bGV6emll",
        "bGV6emllcw==",
        "bGV6enk=",
        "bG1hbw==",
        "bG1mYW8=",
        "bHViZQ==",
        "bHVzdHk=",
        "bWFtcw==",
        "bWFzc2E=",
        "bWFzdGVyYmF0ZQ==",
        "bWFzdGVyYmF0aW5n",
        "bWFzdGVyYmF0aW9u",
        "bWFzdHVyYmF0ZQ==",
        "bWFzdHVyYmF0aW5n",
        "bWFzdHVyYmF0aW9u",
        "bWF4aQ==",
        "bWVuc2Vz",
        "bWVuc3RydWF0ZQ==",
        "bWVuc3RydWF0aW9u",
        "bWV0aA==",
        "bS1mdWNraW5n",
        "bW9mbw==",
        "bW9sZXN0",
        "bW9vbGll",
        "bW9yb24=",
        "bW90aGVyZnVja2E=",
        "bW90aGVyZnVja2Vy",
        "bW90aGVyZnVja2luZw==",
        "bXRoZXJmdWNrZXI=",
        "bXRocmZ1Y2tlcg==",
        "bXRocmZ1Y2tpbmc=",
        "bXVmZg==",
        "bXVmZmRpdmVy",
        "bXV0aGFmdWNrYXo=",
        "bXV0aGFmdWNrZXI=",
        "bXV0aGVyZnVja2Vy",
        "bXV0aGVyZnVja2luZw==",
        "bXV0aHJmdWNraW5n",
        "bmFk",
        "bmFkcw==",
        "bmFrZWQ=",
        "bmFwYWxt",
        "bmVncm8=",
        "bmlnZ2E=",
        "bmlnZ2Fo",
        "bmlnZ2Fz",
        "bmlnZ2F6",
        "bmlnZ2Vy",
        "bmlnZ2Vy",
        "bmlnZ2Vycw==",
        "bmlnZ2xl",
        "bmlnbGV0",
        "bmltcm9k",
        "bmlubnk=",
        "bmlwcGxl",
        "bm9va3k=",
        "bnltcGhv",
        "b3BpYXRl",
        "b3BpdW0=",
        "b3JnYXNt",
        "b3JnYXNtaWM=",
        "b3JnaWVz",
        "b3JneQ==",
        "b3Z1bXM=",
        "cC51LnMucy55Lg==",
        "cGFkZHk=",
        "cGFraQ==",
        "cGFudGll",
        "cGFudGllcw==",
        "cGFudHk=",
        "cGFzdGll",
        "cGNw",
        "cGVja2Vy",
        "cGVkbw==",
        "cGVkb3BoaWxl",
        "cGVkb3BoaWxpYQ==",
        "cGVkb3BoaWxpYWM=",
        "cGVl",
        "cGVlcGVl",
        "cGVuaWFs",
        "cGVuaWxl",
        "cGVuaXM=",
        "cGVydmVyc2lvbg==",
        "cGV5b3Rl",
        "cGhhbGxp",
        "cGhhbGxpYw==",
        "cGh1Y2s=",
        "cGlsbG93Yml0ZXI=",
        "cGltcA==",
        "cGlua28=",
        "cGlzcw==",
        "cGlzc2Vk",
        "cGlzc29mZg==",
        "cGlzcy1vZmY=",
        "cG1z",
        "cG9sYWNr",
        "cG9vbg==",
        "cG9vbnRhbmc=",
        "cG9ybg==",
        "cG9ybm8=",
        "cG9ybm9ncmFwaHk=",
        "cHJpY2s=",
        "cHJpZw==",
        "cHJvc3RpdHV0ZQ==",
        "cHJ1ZGU=",
        "cHViZQ==",
        "cHViaWM=",
        "cHVua2Fzcw==",
        "cHVua3k=",
        "cHVzc2llcw==",
        "cHVzc3k=",
        "cHVzc3lwb3VuZGVy",
        "cHV0bw==",
        "cXVlYWY=",
        "cXVlZWY=",
        "cXVlZWY=",
        "cXVlZXI=",
        "cXVlZXJv",
        "cXVlZXJz",
        "cXVpY2t5",
        "cXVpbQ==",
        "cmFjeQ==",
        "cmFwZQ==",
        "cmFwZWQ=",
        "cmFwZXI=",
        "cmFwaXN0",
        "cmF1bmNo",
        "cmVjdGFs",
        "cmVjdHVt",
        "cmVjdHVz",
        "cmVlZmVy",
        "cmVldGFyZA==",
        "cmVpY2g=",
        "cmV0YXJk",
        "cmV0YXJkZWQ=",
        "cmV2dWU=",
        "cmltam9i",
        "cml0YXJk",
        "cnRhcmQ=",
        "ci10YXJk",
        "cnVtcHJhbW1lcg==",
        "cnVza2k=",
        "cy5oLmkudC4=",
        "cy5vLmIu",
        "czBi",
        "c2FkaXNt",
        "c2FkaXN0",
        "c2NhZw==",
        "c2NhbnRpbHk=",
        "c2NoaXpv",
        "c2NobG9uZw==",
        "c2Nyb2c=",
        "c2Nyb3Q=",
        "c2Nyb3Rl",
        "c2Nyb3R1bQ==",
        "c2NydWQ=",
        "c2VhbWFu",
        "c2VhbWVu",
        "c2VkdWNl",
        "c2VtZW4=",
        "c2V4",
        "c2V4dWFs",
        "c2gxdA==",
        "cy1oLTEtdA==",
        "c2hhbWVkYW1l",
        "c2hpdA==",
        "cy1oLWktdA==",
        "c2hpdGU=",
        "c2hpdGVhdGVy",
        "c2hpdGZhY2U=",
        "c2hpdGhlYWQ=",
        "c2hpdGhvbGU=",
        "c2hpdGhvdXNl",
        "c2hpdHM=",
        "c2hpdHQ=",
        "c2hpdHRlZA==",
        "c2hpdHRlcg==",
        "c2hpdHR5",
        "c2hpeg==",
        "c2lzc3k=",
        "c2thZw==",
        "c2thbms=",
        "c2xhdmU=",
        "c2xlYXpl",
        "c2xlYXp5",
        "c2x1dA==",
        "c2x1dGR1bXBlcg==",
        "c2x1dGtpc3M=",
        "c2x1dHM=",
        "c21lZ21h",
        "c211dA==",
        "c211dHR5",
        "c25pcGVy",
        "c251ZmY=",
        "cy1vLWI=",
        "c29kb20=",
        "c291c2U=",
        "c291c2Vk",
        "c3Blcm0=",
        "c3BpYw==",
        "c3BpY2s=",
        "c3Bpaw==",
        "c3Bpa3M=",
        "c3Bvb2dl",
        "c3B1bms=",
        "c3RmdQ==",
        "c3RpZmZ5",
        "c3RvbmVk",
        "c3Vja2Vk",
        "c3Vja2luZw==",
        "c3Vtb2ZhYmlhdGNo",
        "dDF0",
        "dGFtcG9u",
        "dGFyZA==",
        "dGF3ZHJ5",
        "dGVhYmFnZ2luZw==",
        "dGVhdA==",
        "dGVyZA==",
        "dGVzdGU=",
        "dGVzdGVl",
        "dGVzdGVz",
        "dGVzdGljbGU=",
        "dGVzdGlz",
        "dGlua2xl",
        "dGl0",
        "dGl0ZnVjaw==",
        "dGl0aQ==",
        "dGl0cw==",
        "dGl0dGllZnVja2Vy",
        "dGl0dGllcw==",
        "dGl0dHk=",
        "dGl0dHlmdWNr",
        "dGl0dHlmdWNrZXI=",
        "dG9rZQ==",
        "dHJhbnNzZXh1YWw=",
        "dHJhc2h5",
        "dHViZ2lybA==",
        "dHVyZA==",
        "dHVzaA==",
        "dHdhdA==",
        "dHdhdHM=",
        "dW5kaWVz",
        "dW53ZWQ=",
        "dXJpbmFs",
        "dXJpbmU=",
        "dXRlcnVz",
        "dXpp",
        "dmFn",
        "dmFnaW5h",
        "dmFsaXVt",
        "dmlhZ3Jh",
        "dmlyZ2lu",
        "dm9ka2E=",
        "dm9taXQ=",
        "dm95ZXVy",
        "dnVsdmE=",
        "d2Fk",
        "d2FuZw==",
        "d2Fuaw==",
        "d2Fua2Vy",
        "d2F6b28=",
        "d2VkZ2ll",
        "d2Vlbmll",
        "d2Vld2Vl",
        "d2VpcmRv",
        "d2VuY2g=",
        "d2V0YmFjaw==",
        "d2gwcmU=",
        "d2gwcmVmYWNl",
        "d2hpdGV5",
        "d2hvcmFsaWNpb3Vz",
        "d2hvcmU=",
        "d2hvcmVhbGljaW91cw==",
        "d2hvcmVk",
        "d2hvcmVmYWNl",
        "d2hvcmVob3BwZXI=",
        "d2hvcmVob3VzZQ==",
        "d2hvcmVz",
        "d2hvcmluZw==",
        "d2lnZ2Vy",
        "d29vZHk=",
        "d29w",
        "d3Rm",
        "eC1yYXRlZA==",
        "eHh4",
        "eWVhc3R5",
        "eW9iYm8=",
        "em9vcGhpbGU=",
        "cGxlYg==",
      ];
      var d = a;
      const m = [
          "am91IGRvbm5lcg==",
          "dm9ldHNlaw==",
          "Sm91IG1vZXI=",
          "Zm9r",
          "Zm9rb2Y=",
          "Ymxpa3NlbQ==",
          "cG9lcw==",
          "ZG9vcw==",
          "c2tlZWZibGlrc2Vt",
          "Y3VudA==",
          "dGllZg==",
          "bmFhaQ==",
          "ZG9uZGVy",
          "c2Vrcw==",
          "Z2F0IGxla2tlcg==",
          "d2lw",
          "dHJlayAnbiBob2VuZGVy",
          "dHJlayBuIGhvZW5kZXI=",
          "aG90bm90",
          "Ym9lc21hbg==",
          "a2FmZmVy",
          "dnJlZXQ=",
          "c21lZXI=",
          "c290",
          "YmVmb2s=",
          "Ym9rbmFhaQ==",
          "bHVs",
          "YmFsbGFz",
          "aG9sbmFhaQ==",
          "c25vdG5ldXM=",
          "c3VpcA==",
          "YmFsc2Fr",
          "d2lwZ2F0",
          "cGllbGtvcA==",
          "bW9mZmll",
          "c2tvbGxpZQ==",
          "YmVyZ2ll",
          "Z2xhbnM=",
        ],
        t = ["dmFn", "aGVtcA==", "bWFtcw==", "aG9vcg==", "YmVlcg=="];
      var n = Z(18349);
      const V = { en_GB: [...d], af_ZA: [...d, ...m] },
        Y = { en_GB: [], af_ZA: [...t] };
      function G(c, l = "en_GB", Z = !1) {
        try {
          const a = unescape(encodeURIComponent(c));
          if ("string" === typeof a) {
            const c = b(l, Z);
            for (const l of c)
              if (a.toLowerCase().includes((0, n.decode)(l).toLowerCase()))
                return !0;
          }
        } catch (a) {
          console.error(a);
        }
        return !1;
      }
      function e(c, l = "en_GB", Z = !1) {
        try {
          if ("string" === typeof c) {
            const a = c.split(" ");
            for (const c of a) {
              const a = unescape(encodeURIComponent(c)),
                d = a.replace(/[\W_]+/g, "");
              if ("string" === typeof a && "string" === typeof d) {
                const c = b(l, Z);
                for (const l of c)
                  if (
                    (0, n.encode)(a.toLowerCase()) === l ||
                    (0, n.encode)(d.toLowerCase()) === l
                  )
                    return !0;
              }
            }
          }
        } catch (a) {
          console.error(a);
        }
        return !1;
      }
      function b(c = "en_GB", l = !1) {
        const Z = V[c];
        if (!Z) return V.en_GB;
        if (!l || !Y[c]) return Z;
        const a = Y[c];
        return a ? Z.filter((c) => !a.includes(c)) : Z;
      }
    },
    93523: function (c, l, Z) {
      "use strict";
      var a = Z(31635),
        d = Z(18657),
        m = Z(40834),
        t = Z(7504),
        n = Z(91896);
      let V = class extends m.A {
        get _store() {
          return this.$store;
        }
        shuffleArray(c) {
          for (let l = c.length - 1; l > 0; l--) {
            const Z = Math.floor(Math.random() * (l + 1)),
              a = c[l];
            ((c[l] = c[Z]), (c[Z] = a));
          }
          return c;
        }
        get isProduction() {
          return (
            "production" ===
              {
                NODE_ENV: "production",
                BASE_URL: "/",
                SERVER_INFO: {
                  env: "production",
                  targetEnv: "production",
                  awsProfile: "terraform-production",
                  terraformBucket: "terraform.edshed.com",
                  staticBucket: {
                    name: "files.edshed.com",
                    region: "eu-west-2",
                  },
                  api: "https://api.edshed.com/",
                  auth: "https://www.edshed.com/",
                  hub: "https://admin.edshed.com/",
                  hubOld: "https://hub.edshed.com/",
                  game: "https://play.edshed.com/",
                  spelling: "https://www.spellingshed.com/",
                  maths: "https://www.mathshed.com/",
                  litplus: "https://www.literacyshedplus.com/",
                  quiz: "https://www.quizshed.com/",
                  phonics: "https://www.phonicsshed.com/",
                  lit: "https://www.literacyshed.com/",
                  edshedza: "https://www.edshed.co.za/",
                  spellingMarketing: "https://www.spellingshed.com/",
                  edshedHub: "https://hub.edshed.com/",
                  domain: "edshed.com",
                },
                SERVER: "https://api.edshed.com/",
                AUTH_URI: "https://www.edshed.com/",
                PACKAGE_VERSION: "1.24.16",
              }.TARGET_ENV && !0
          );
        }
        randomString(c) {
          let l = "";
          const Z = "abcdefghijklmnopqrstuvwxyz";
          for (let a = 0; a < c; a++)
            l += Z.charAt(Math.floor(Math.random() * Z.length));
          return l;
        }
        get config() {
          return t.A;
        }
        i18nLocaleFormat(c) {
          const l = c.split("-");
          return (l[1] && (l[1] = l[1].toUpperCase()), l.join("_"));
        }
        setUserData(c) {
          var l, Z, a, d, m, t, n;
          if (!c) return;
          (this._store.commit("SET_USER", c),
            c.token && this._store.commit("SET_TOKEN", c.token),
            this._store.commit(
              "SET_MUSIC",
              !0 ===
                (null === (l = c.settings) || void 0 === l
                  ? void 0
                  : l.musicOn),
            ),
            this._store.commit(
              "SET_SOUNDFX",
              !0 ===
                (null === (Z = c.settings) || void 0 === Z
                  ? void 0
                  : Z.soundFXOn),
            ),
            this._store.commit(
              "SET_LETTERNAMES",
              !0 ===
                (null === (a = c.settings) || void 0 === a
                  ? void 0
                  : a.letterNamesOn),
            ),
            this._store.commit(
              "SET_DISABLE_TIMERS",
              !0 ===
                (null === (d = c.settings) || void 0 === d
                  ? void 0
                  : d.disableTimer),
            ),
            this._store.commit(
              "SET_INVERTCALC",
              !0 ===
                (null === (m = c.settings) || void 0 === m
                  ? void 0
                  : m.invertCalcOn),
            ));
          const V = c.school,
            Y =
              void 0 === V ||
              1 === V.teacher ||
              1 === V.admin ||
              null ===
                (null === (t = V.settings) || void 0 === t
                  ? void 0
                  : t.fontPreference) ||
              void 0 ===
                (null === (n = V.settings) || void 0 === n
                  ? void 0
                  : n.fontPreference);
          this._store.commit("SET_CAN_CHANGE_FONT", Y);
          let G = "sassoon";
          switch (c.locale) {
            case "en_US":
              G = "sassoonUs";
              break;
            case "en_ZA":
              G = "sassoonZa";
              break;
            default:
              G = "sassoon";
              break;
          }
          var e, b, o;
          Y
            ? (G =
                (null === (e = c.settings) || void 0 === e
                  ? void 0
                  : e.fontPreference) ||
                (null === V ||
                void 0 === V ||
                null === (b = V.settings) ||
                void 0 === b
                  ? void 0
                  : b.fontPreference) ||
                G)
            : (G =
                (null === V ||
                void 0 === V ||
                null === (o = V.settings) ||
                void 0 === o
                  ? void 0
                  : o.fontPreference) || G);
          this._store.commit("SET_FONT", G);
        }
        async logError(c, l, Z, a) {
          try {
            var d, m;
            const t = {
              clientTimestamp: Date.now(),
              data: null !== l && void 0 !== l ? l : {},
              key: null !== Z && void 0 !== Z ? Z : "",
              message: c.message,
              trace: null !== (d = c.stack) && void 0 !== d ? d : "",
              userId:
                null === (m = this._store.state.user) || void 0 === m
                  ? void 0
                  : m.id,
              logGroup: "play",
              errorRef: a,
            };
            (console.log(t), await n.H.logClientError(t));
          } catch (t) {
            console.error("failed to log error", t);
          }
        }
      };
      ((V = (0, a.Cg)([d.uA], V)), (l.A = V));
    },
  },
]);
//# sourceMappingURL=4328.feed0218.js.map
