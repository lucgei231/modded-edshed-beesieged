"use strict";
(
  self["webpackChunkgame"] = self["webpackChunkgame"] || []
).push([
  [4547],
  {
    1519: function (e, d, a) {
      a.d(d, {
        X: function () {
          return o;
        },
      });
      a(18111);
      a(7588);
      var n = a(20984);

      function t(...e) {
        const d = [];
        return (
          e.forEach((e) => {
            d[e[0]] = e[1];
          }),
          d
        );
      }

      const o = {
        bug: {
          key: "bug",
          name: "Bug",
          description: "The standard bug. They will mindlessly charge towards the gate.",
          options: { health: 1, resistance: [], weakness: [], value: 1 },
          path: { speed: 22 },
        },
        bigbug: {
          key: "bigbug",
          name: "Big Bug",
          description:
            "A heavy duty bug. Vastly stronger than the standard bug, but much slower.",
          options: { health: 10, resistance: [], weakness: [], value: 10 },
          path: { speed: 14 },
        },
        ant: {
          key: "ant",
          name: "Ant",
          description:
            "Ants are too small for most bees to see, buy a <b>Ranger Bee</b> to deal with them!",
          options: {
            health: 1,
            resistance: [],
            weakness: [],
            value: 1,
            effects: t([n.R.Small, -1]),
          },
          path: { speed: 25 },
        },
        worm: {
          key: "worm",
          name: "Worm",
          description: "Worms bury underground and cannot be attacked until they surface.",
          options: {
            health: 1,
            resistance: [],
            weakness: [],
            value: 1,
            effects: t([n.R.Hidden, -1]),
          },
          path: { speed: 19, lockRotation: !0, preventKnockback: !0 },
        },
        bugbus: {
          key: "bugbus",
          name: "Bug Bus",
          description:
            "The Bug Bus carries other bugs. When it is defeated, those other bugs will jump out, be aware!",
          options: {
            health: 10,
            resistance: [],
            weakness: [],
            value: 10,
            spawnsEnemies: !0,
          },
          path: { speed: 15 },
        },
        bear: {
          key: "bear",
          name: "Bear",
          description:
            "A bear is looking for honey! Don't let it reach the gate or it will cause massive damage!",
          options: { health: 150, resistance: [], weakness: [], value: 100 },
          path: { speed: 14 },
        },
        bear_arm: {
          key: "bear_arm",
          name: "[bear arm piece]",
          options: {
            health: 1,
            resistance: [],
            weakness: [],
            value: 0,
            effects: t([n.R.Immune, -1]),
          },
          path: { speed: 0, progress: 0.1 },
        },
      };
    },

    20984: function (e, d, a) {
      a.d(d, {
        R: function () {
          return n;
        },
      });
      var n;
      (function (e) {
        e[(e["Honey"] = 0)] = "Honey";
        e[(e["Poison"] = 1)] = "Poison";
        e[(e["Fire"] = 2)] = "Fire";
        e[(e["Burn"] = 3)] = "Burn";
        e[(e["Ice"] = 4)] = "Ice";
        e[(e["Fast"] = 5)] = "Fast";
        e[(e["Slow"] = 6)] = "Slow";
        e[(e["Weak"] = 7)] = "Weak";
        e[(e["Shield"] = 8)] = "Shield";
        e[(e["Immune"] = 9)] = "Immune";
        e[(e["Frozen"] = 10)] = "Frozen";
        e[(e["Small"] = 11)] = "Small";
        e[(e["Hidden"] = 12)] = "Hidden";
        e[(e["Aggro"] = 13)] = "Aggro";
        e[(e["Stopped"] = 14)] = "Stopped";
        e[(e["Corroding"] = 15)] = "Corroding";
      })(n || (n = {}));
    },

    28325: function (e, d, a) {
      a.d(d, {
        N: function () {
          return t;
        },
      });
      var n = a(91114);
      a(44114);

      class t {
        constructor() {
          (0, n.A)(this, "round", { waves: [] });
        }

        add(e) {
          return this.round.waves.push(e), this;
        }

        done() {
          return this.round;
        }
      }
    },

    35060: function (e, d, a) {
      a.d(d, {
        Q: function () {
          return t;
        },
      });
      var n = a(91114);
      a(44114);

      class t {
        constructor(e = 2000, d = 1, a = !1) {
          (0, n.A)(this, "wave", { enemies: [], delay: 2000, spawnRate: 1, shuffle: !1 });
          this.wave.delay = e;
          this.wave.spawnRate = d;
          this.wave.shuffle = a;
        }

        add(e, d = 1, a = 1, n = []) {
          for (let t = 0; t < d; t++) this.wave.enemies.push({ key: e, rank: a, effects: n });
          return this;
        }

        pause(e = 1) {
          return this.add("", e);
        }

        done() {
          return this.wave;
        }
      }
    },

    43236: function (e, d, a) {
      a.d(d, {
        LK: function () {
          return g;
        },
        NB: function () {
          return r;
        },
        VV: function () {
          return u;
        },
        WG: function () {
          return s;
        },
        pK: function () {
          return i;
        },
      });
      a(44114);
      a(27495);
      a(25440);
      a(62953);
      var n = a(35060),
        t = a(28325),
        o = a(20984);

      function s(e, d) {
        if (d <= 1) return e;
        if (1 === e && 3 === d) return 3;
        let a = e;
        for (let n = 0; n < d - 1; n++) a = Math.ceil(1.5 * a);
        return a;
      }

      function i(e, d) {
        return d <= 1 ? e : Math.round(e + 1.5 * d);
      }

      function r(e, d) {
        if (d <= 1) return e;
        const a = e;
        return a * d;
      }

      function g(e, d) {
        if ("bugbus" === e) {
          const e = h[d];
          return [...e.enemies];
        }
        return [];
      }

      function u(e, d) {
        const a = b(e, d),
          s = e % 10,
          i = new t.N();
        let r = "mixed";
        if (
          (r = 9 === s ? "bear" : s >= 0 && s < 5 ? (d < 0.5 ? "mixed" : "fixed") : 5 === s ? (d < 0.5 ? "fixed" : "silly") : s > 5 && s < 8 ? (d < 0.5 ? "mixed" : "fixed") : d < 0.5 ? "fixed" : "hard"),
          "bear" === r
        ) {
          const e = d > 0.3 && d < 0.8,
            t = Math.min(10, e ? a : a + 1),
            s = d > 0.1 && d < 0.4,
            r = d > 0.7,
            g = [];
          return e && g.push(o.R.Shield), s && g.push(d < 0.5 ? o.R.Fire : o.R.Ice), r && g.push(o.R.Aggro), i.add(new n.Q(0, 1, !1).add("bear", 1, t, g).done()).done();
        }

        if ("mixed" === r) {
          const e = new n.Q(0, 2, !0),
            t = c(a, d);
          for (let d = 0; d < t.length; d++) {
            const a = t[d];
            e.add(a.key, a.amount, a.rank, a.effects);
          }
          return i.add(e.done()).done();
        }

        if ("fixed" === r) {
          const e = new n.Q(0, 2, !0),
            t = w(a, d);
          for (let d = 0; d < t.length; d++) {
            const a = t[d];
            e.add(a.key, a.amount, a.rank, a.effects);
          }
          return i.add(e.done()).done();
        }

        if ("silly" === r) {
          const e = ["bug", "bigbug", "bug", "ant", "worm", "bugbus"],
            t = e[Math.floor(e.length * d)] || "bug",
            o = Math.max(1, a - 2);
          Math.abs(Math.min(0, 6 - o));
          return i.add(new n.Q(0, 2, !1).add(t, 100, Math.max(1, a - 2)).done()).done();
        }

        if ("hard" === r) {
          const e = ["bug", "bigbug", "bug", "ant", "worm", "bugbus"],
            t = e[Math.floor(e.length * d)] || "bug";
          return i.add(new n.Q(0, 2, !1).add(t, 3, Math.min(10, Math.max(1, a + 2))).done()).done();
        }

        return i.add(new n.Q(0, 10, !1).add("bug", 300, 1).done()).done();
      }

      function b(e, d) {
        let a = Math.min(10, Math.floor(e / 10) - Math.round(d)) - 1;
        return e > 100 && (a = Math.min(10, a + 1)), e > 200 && (a = 10), a;
      }

      function c(e, d) {
        const a = d
            .toString()
            .replace(".", "")
            .slice(1)
            .split(""),
          n = [];
        let t = 0;
        for (let s = 0; s < 25; s++) (t >= a.length && (t = 0), n.push(parseInt(a[t] || "5") / 10), t++);
        const o = [];
        for (let s = 0; s < 5; s++) {
          const d = s + 4 >= n.length ? 0 : s,
            a = l(s),
            t = Math.floor(n[d + 0] * a.length),
            i = a[t] || "bug",
            r = p(e, n.slice(d, d + 4), i);
          o.push(r);
        }
        return o;
      }

      function w(e, d) {
        const a = d
            .toString()
            .replace(".", "")
            .slice(1)
            .split(""),
          n = [],
          t = ["bug", "bigbug", "bug", "ant", "worm", "bugbus"],
          o = t[Math.floor(t.length * d)] || "bug",
          s = [];
        let i = 0;
        for (let r = 0; r < 25; r++) (i >= a.length && (i = 0), n.push(parseInt(a[i] || "5") / 10), i++);
        for (let r = 0; r < 4; r++) {
          const d = r + 4 >= n.length ? 0 : r,
            a = p(e, n.slice(d, d + 4), o);
          s.push(a);
        }
        return s;
      }

      function p(e, d, a) {
        const n = d[0] > 0.5,
          t = d[1] > 0.7,
          s = d[1] < 0.3,
          i = d[2] < 0.2,
          r = Math.round(4 * d[3]) - 3,
          g = Math.min(10, Math.max(1, e + r)),
          u = [];
        n && u.push(o.R.Shield);
        t && u.push(o.R.Fire);
        s && u.push(o.R.Ice);
        i && u.push(o.R.Aggro);
        const b = m(a, r, !!u.length),
          c = 0.2 * Math.abs(Math.min(0, 6 - g)),
          w = Math.max(1, Math.ceil(b - b * c));
        return { key: a, rank: g, amount: w, effects: u };
      }

      function l(e) {
        switch (e) {
          case 0:
            return ["bug"];
          case 1:
            return ["bug", "bug", "bigbug"];
          case 2:
            return ["bug", "bigbug"];
          case 3:
            return ["ant", "ant", "worm"];
          case 4:
            return ["bugbus", "worm"];
          default:
            return ["bug"];
        }
      }

      function m(e, d, a) {
        let n = 20;
        return (
          "bigbug" === e && (n = 5),
          "ant" === e && (n = 10),
          "bugbus" === e && (n = 2),
          "worm" === e && (n = 8),
          d > 0 && (n *= 0.3),
          -1 === d && (n *= 1.5),
          d < -1 && (n *= 2),
          a && (n *= 0.75),
          Math.ceil(n)
        );
      }

      const h = [];
      h[1] = new n.Q(0, 1).add("bug", 10, 2, []).add("bug", 5, 3, []).done();
      h[2] = new n.Q(0, 1).add("bug", 10, 3, []).add("bug", 5, 2, []).done();
      h[3] = new n.Q(0, 1).add("bug", 20, 4, []).add("bug", 10, 3, []).add("bigbug", 1, 2, []).done();
      h[4] = new n.Q(0, 1).add("bug", 10, 3, []).add("bug", 20, 4, []).add("bug", 10, 5, []).add("bigbug", 1, 3, []).add("ant", 10, 3, []).done();
      h[5] = new n.Q(0, 1).add("bug", 10, 5, []).add("bug", 20, 4, []).add("bug", 10, 3, []).add("bigbug", 2, 4, []).add("ant", 10, 3, []).done();
      h[6] = new n.Q(0, 1).add("bug", 10, 6, []).add("bug", 20, 5, []).add("bug", 10, 4, []).add("bigbug", 2, 5, []).add("ant", 10, 4, []).done();
      h[7] = new n.Q(0, 1).add("bug", 10, 7, []).add("bug", 20, 6, []).add("bug", 10, 5, []).add("bigbug", 2, 6, []).add("ant", 10, 5, []).done();
      h[8] = new n.Q(0, 1).add("bug", 3, 8, []).add("bigbug", 1, 7, []).add("bigbug", 4, 6, []).add("ant", 10, 6, []).done();
      h[9] = new n.Q(0, 1).add("bug", 10, 7, []).add("bug", 5, 8, []).add("bigbug", 1, 8, []).add("bigbug", 2, 7, []).add("ant", 15, 7, []).done();
      h[10] = new n.Q(0, 1).add("bug", 2, 9, []).add("bug", 5, 8, []).add("bug", 10, 7, []).add("bigbug", 2, 7, []).add("bigbug", 1, 9, []).add("bigbug", 1, 8, []).add("ant", 20, 6, []).done();
    },

    58991: function (e, d, a) {
      a.d(d, {
        A: function () {
          return i;
        },
      });
      a(62953);
      var n = a(28325),
        t = a(35060);
      const o = [];
      var s = o;
      o[0] = new n.N().add(new t.Q(0, 1, !1).add("bug", 5, 1, []).done()).done();
      o[1] = new n.N().add(new t.Q(0, 1, !1).add("bug", 15, 1, []).done()).done();
      o[2] = new n.N().add(new t.Q(0, 1, !1).add("bug", 20, 1, []).done()).done();
      o[3] = new n.N().add(new t.Q(0, 1, !1).add("bug", 20, 1, []).done()).add(new t.Q(4000, 1, !1).add("bigbug", 1, 1, []).done()).done();
      o[4] = new n.N().add(new t.Q(0, 1, !1).add("bug", 30, 1, []).done()).add(new t.Q(0, 1, !1).add("bigbug", 1, 1, []).done()).add(new t.Q(3000, 1, !1).add("bigbug", 1, 1, []).done()).done();
      o[5] = new n.N().add(new t.Q(0, 1, !1).add("bigbug", 2, 1, []).done()).add(new t.Q(4000, 1, !1).add("bigbug", 1, 1, []).done()).done();
      o[6] = new n.N().add(new t.Q(0, 1, !1).add("bug", 20, 1, []).add("bug", 5, 2, []).add("bigbug", 1, 1, []).done()).done();
      o[7] = new n.N().add(new t.Q(0, 1, !0).add("bug", 10, 2, []).add("bug", 1, 3, []).add("bigbug", 1, 1, []).add("bug", 30, 1, []).done()).done();
      o[8] = new n.N().add(new t.Q(0, 1, !0).add("bigbug", 1, 2, []).add("bigbug", 2, 1, []).add("bug", 2, 3, []).add("bug", 10, 2, []).add("bug", 30, 1, []).done()).done();
      o[9] = new n.N().add(new t.Q(0, 1, !1).add("bigbug", 1, 2, []).add("bug", 20, 2, []).add("bug", 5, 3, []).add("bug", 30, 1, []).done()).add(new t.Q(4000, 1, !1).add("bigbug", 1, 2, []).done()).done();
      o[10] = new n.N().add(new t.Q(0, 1, !1).add("bear", 1, 1, []).done()).done();
      o[11] = new n.N().add(new t.Q(0, 2, !0).add("bug", 10, 3, []).add("bug", 25, 2, []).add("bug", 30, 1, []).add("bigbug", 2, 2, []).add("bigbug", 2, 1, []).done()).done();
      o[12] = new n.N().add(new t.Q(0, 1, !1).add("bug", 10, 3, []).add("bigbug", 3, 1, []).done()).add(new t.Q(5000, 1, !0).add("bigbug", 2, 2, []).add("bug", 20, 2, []).done()).done();
      o[13] = new n.N().add(new t.Q(0, 2, !1).add("bug", 20, 1, []).add("bigbug", 1, 3, []).add("bug", 20, 2, []).add("bug", 15, 3, []).done()).done();
      o[14] = new n.N().add(new t.Q(0, 2, !1).add("ant", 10, 1, []).done()).done();
      o[15] = new n.N().add(new t.Q(0, 1, !1).add("bigbug", 1, 3, []).done()).add(new t.Q(5000, 1, !0).add("ant", 10, 1, []).add("ant", 5, 2, []).done()).done();
      o[16] = new n.N().add(new t.Q(0, 1, !0).add("bug", 30, 3, []).add("bug", 20, 2, []).add("ant", 30, 1, []).add("ant", 10, 2, []).add("bigbug", 2, 2, []).add("bigbug", 1, 3, []).done()).done();
      o[17] = new n.N().add(new t.Q(0, 1, !1).add("bug", 20, 1, [8]).done()).done();
      o[18] = new n.N().add(new t.Q(0, 1, !1).add("bug", 20, 1, [8]).add("bug", 5, 2, [8]).add("bug", 30, 3, []).done()).done();
      o[19] = new n.N().add(new t.Q(0, 1, !1).add("bear", 1, 2, []).done()).done();
      o[20] = new n.N().add(new t.Q(0, 1, !1).add("worm", 1, 1, []).done()).add(new t.Q(5000, 1, !0).add("bug", 10, 4, []).add("worm", 5, 1, []).add("bug", 10, 3, []).done()).done();
      o[21] = new n.N().add(new t.Q(0, 1, !0).add("bug", 10, 2, [8]).add("bug", 10, 4, []).add("ant", 20, 2, []).add("worm", 10, 1, []).add("worm", 1, 2, []).done()).done();
      o[22] = new n.N().add(new t.Q(0, 2, !0).add("bigbug", 2, 3, []).add("bigbug", 1, 1, [8]).add("bug", 10, 4, []).add("bigbug", 1, 1, [8]).add("ant", 5, 1, []).add("ant", 10, 2, []).add("worm", 5, 2, []).done()).done();
      o[23] = new n.N().add(new t.Q(0, 2, !0).add("bug", 10, 3, [8]).add("bug", 10, 2, [8]).add("bigbug", 2, 1, [8]).add("worm", 1, 1, [8]).add("bug", 10, 1, [8]).done()).done();
      o[24] = new n.N().add(new t.Q(0, 1, !1).add("bug", 10, 1, [8]).add("ant", 10, 2, []).add("ant", 5, 3, []).add("bug", 40, 2, []).add("bug", 20, 3, []).add("bug", 10, 4, []).add("bug", 5, 5, []).done()).done();
      o[25] = new n.N().add(new t.Q(0, 1, !1).add("bugbus", 1, 1, []).done()).add(new t.Q(10000, 1, !1).add("bugbus", 2, 1, []).add("ant", 20, 1, []).add("worm", 10, 1, []).add("worm", 5, 2, []).add("bug", 10, 4, []).done()).done();
      o[26] = new n.N().add(new t.Q(0, 1, !1).add("bigbug", 4, 3, []).done()).add(new t.Q(3000, 1, !1).add("bigbug", 1, 2, [8]).add("bug", 10, 2, [8]).add("bug", 10, 3, [8]).add("bug", 20, 4, []).add("bug", 5, 5, []).done()).done();
      o[27] = new n.N().add(new t.Q(0, 1, !1).add("bugbus", 2, 1, []).add("bugbus", 1, 2, []).done()).add(new t.Q(300, 2, !0).add("bigbug", 5, 4, []).add("bug", 30, 1, []).add("bug", 30, 2, []).add("bug", 20, 3, []).done()).add(new t.Q(2000, 1, !1).add("bugbus", 1, 3, []).done()).done();
      o[28] = new n.N().add(new t.Q(0, 2, !1).add("bugbus", 1, 3, []).add("ant", 10, 3, []).add("worm", 5, 2, []).add("worm", 5, 3, []).add("bugbus", 3, 1, []).done()).done();
      o[29] = new n.N().add(new t.Q(0, 1, !1).add("bear", 1, 2, [8]).done()).done();
      o[30] = new n.N().add(new t.Q(0, 1, !1).add("bug", 20, 3, [2]).add("bigbug", 1, 3, [2]).done()).add(new t.Q(2000, 2, !0).add("ant", 10, 3, [2]).add("ant", 5, 4, [2]).done()).done();
      o[31] = new n.N().add(new t.Q(0, 1, !1).add("bigbug", 4, 2, [2]).done()).add(new t.Q(2000, 1, !0).add("bug", 10, 5, []).add("ant", 5, 5, []).add("worm", 5, 4, []).add("bug", 20, 3, []).done()).done();
      o[32] = new n.N().add(new t.Q(0, 1, !1).add("bugbus", 1, 1, [2]).done()).add(new t.Q(6000, 1, !1).add("bugbus", 4, 1, [2]).done()).done();
      o[33] = new n.N().add(new t.Q(0, 2, !0).add("bug", 10, 3, [2, 8]).add("bigbug", 2, 2, [8]).add("bug", 30, 4, []).add("bigbug", 1, 3, []).done()).done();
      o[34] = new n.N().add(new t.Q(0, 1, !1).add("bugbus", 1, 2, [2]).done()).add(new t.Q(3000, 1, !1).add("worm", 5, 3, [2]).add("worm", 5, 1, []).done()).add(new t.Q(0, 2, !0).add("ant", 10, 2, [8]).add("bigbug", 1, 3, [2, 8]).done()).done();
      o[35] = new n.N().add(new t.Q(0, 1, !1).add("bugbus", 1, 1, [8]).done()).add(new t.Q(5000, 1, !1).add("bugbus", 3, 1, [8]).done()).add(new t.Q(3000, 1, !1).add("bugbus", 1, 2, [8]).add("worm", 10, 2, [8]).add("ant", 10, 4, []).add("bug", 20, 5, []).add("bug", 5, 6, []).done()).done();
      o[36] = new n.N().add(new t.Q(0, 1, !1).add("bigbug", 1, 4, [2, 8]).add("bug", 10, 5, []).add("bug", 20, 3, [2]).add("bug", 20, 2, [8]).add("ant", 10, 3, [2]).add("ant", 10, 2, [8]).done()).done();
      o[37] = new n.N().add(new t.Q(0, 1, !1).add("bug", 5, 6, []).done()).add(new t.Q(0, 1, !1).add("worm", 10, 4, []).add("ant", 10, 3, [2]).done()).add(new t.Q(0, 1, !1).add("bugbus", 1, 2, [8]).add("bugbus", 1, 2, [2]).done()).done();
      o[38] = new n.N().add(new t.Q(0, 1, !1).add("bugbus", 5, 1, []).done()).add(new t.Q(5000, 1, !1).add("bugbus", 1, 2, [2, 8]).done()).add(new t.Q(0, 1, !1).add("bigbug", 3, 3, [2, 8]).done()).done();
      o[39] = new n.N().add(new t.Q(0, 1, !1).add("bear", 1, 3, [2, 8]).done()).done();
      o[40] = new n.N().add(new t.Q(0, 3, !1).add("bug", 30, 3, [4]).add("ant", 10, 5, []).done()).add(new t.Q(0, 1, !1).add("bigbug", 4, 5, [4]).done()).done();
      o[41] = new n.N().add(new t.Q(0, 1, !1).add("bugbus", 1, 3, [4]).done()).add(new t.Q(3000, 2, !1).add("bug", 5, 4, [2]).add("bug", 5, 4, [4]).add("bug", 10, 4, [2]).add("bug", 10, 4, [4]).add("bug", 20, 4, [2]).add("bug", 20, 4, [4]).add("bug", 10, 5, [2]).add("bug", 10, 5, [4]).done()).done();
      o[42] = new n.N().add(new t.Q(0, 2, !0).add("ant", 5, 3, [4, 8]).add("ant", 5, 5, []).add("ant", 1, 6, []).add("ant", 20, 1, []).add("ant", 5, 3, [2, 8]).done()).done();
      o[43] = new n.N().add(new t.Q(0, 1, !1).add("worm", 10, 4, []).add("bugbus", 1, 3, [4]).add("bugbus", 1, 3, [2]).done()).add(new t.Q(5000, 1, !1).add("bugbus", 1, 3, [8]).done()).done();
      o[44] = new n.N().add(new t.Q(0, 1, !1).add("bigbug", 2, 5, [4]).add("bigbug", 2, 5, [2]).add("bigbug", 1, 4, [2, 8]).add("bug", 20, 5, []).add("bug", 30, 3, [8]).add("bug", 10, 6, []).done()).done();
      o[45] = new n.N().add(new t.Q(0, 2, !0).add("ant", 10, 5, []).add("bug", 10, 5, []).add("bigbug", 5, 5, []).add("worm", 10, 5, []).add("bugbus", 1, 5, []).done()).done();
      o[46] = new n.N().add(new t.Q(0, 2, !1).add("bigbug", 5, 5, [4, 8]).done()).add(new t.Q(0, 1, !1).add("bugbus", 2, 4, [4]).done()).done();
      o[47] = new n.N().add(new t.Q(0, 2, !0).add("ant", 10, 6, []).add("ant", 20, 2, []).add("bug", 50, 3, [8]).add("bug", 20, 4, [4, 8]).add("bug", 20, 4, [2, 8]).add("worm", 10, 3, [8]).add("bug", 10, 5, [4]).add("bigbug", 5, 5, [4]).done()).done();
      o[48] = new n.N().add(new t.Q(0, 1, !0).add("worm", 10, 1, []).add("worm", 10, 1, [8]).add("worm", 5, 2, []).add("worm", 5, 2, [8]).add("worm", 5, 3, []).add("worm", 5, 4, [8]).add("bug", 10, 5, []).done()).done();
      o[49] = new n.N().add(new t.Q(0, 1, !1).add("bear", 1, 4, [4, 8]).done()).done();
      o[50] = new n.N().add(new t.Q(0, 1, !0).add("bug", 20, 5, [13]).add("bug", 20, 4, [13]).add("bug", 10, 6, [13]).add("bigbug", 2, 5, [13]).done()).done();
      o[51] = new n.N().add(new t.Q(0, 1, !0).add("ant", 10, 4, [13]).add("bigbug", 5, 4, [13]).add("bug", 20, 5, [13]).add("worm", 5, 5, []).add("bugbus", 2, 5, []).done()).done();
      o[52] = new n.N().add(new t.Q(0, 1, !0).add("bug", 10, 5, [8]).add("bug", 10, 4, [13, 2, 8]).add("bigbug", 3, 4, [13]).add("bigbug", 1, 4, [13, 2, 8]).add("worm", 5, 6, []).add("bugbus", 2, 4, [13]).add("ant", 10, 3, [13, 8]).add("ant", 10, 2, [13, 2, 8]).done()).done();
      o[53] = new n.N().add(new t.Q(0, 1, !0).add("worm", 10, 1, [13]).add("worm", 10, 2, [13]).add("worm", 10, 3, [13]).add("worm", 10, 4, [13]).add("bug", 10, 5, [13]).add("worm", 10, 6, [13]).done()).done();
      o[54] = new n.N().add(new t.Q(0, 2, !0).add("bugbus", 2, 4, []).add("bug", 30, 4, [8]).add("bug", 20, 4, [13, 4]).add("bigbug", 5, 4, [13, 4]).add("bigbug", 5, 3, [13, 4, 8]).add("bug", 20, 5, [4, 8]).add("ant", 10, 4, [13, 4]).add("ant", 5, 5, [13]).done()).done();
      o[55] = new n.N().add(new t.Q(0, 1, !1).add("bigbug", 1, 7, [13, 8]).done()).done();
      o[56] = new n.N().add(new t.Q(0, 3, !1).add("bug", 100, 3, [13, 2, 8]).done()).done();
      o[57] = new n.N().add(new t.Q(0, 2, !0).add("bigbug", 2, 6, [2, 8]).add("worm", 5, 4, []).add("bug", 30, 5, [13]).done()).done();
      o[58] = new n.N().add(new t.Q(0, 2, !0).add("ant", 10, 5, [2, 8]).add("worm", 5, 4, []).add("bug", 20, 5, []).add("bug", 10, 6, []).add("bug", 30, 4, []).add("ant", 10, 5, [4, 8]).add("bigbug", 10, 1, [8]).add("bigbug", 5, 2, [8]).done()).done();
      o[59] = new n.N().add(new t.Q(0, 1, !1).add("bear", 1, 5, [13, 8]).done()).done();

      var i = [...s];
    },

    65452: function (e, d, a) {
      a.d(d, {
        V: function () {
          return n;
        },
      });
      const n = {
        bee: {
          key: "bee",
          name: "Bee",
          cost: 240,
          texture: "bee",
          origin: { x: 0.5, y: 0.9 },
          attackOrigin: { x: 0.5, y: 0.7 },
          radius: 32,
          description: "Will sting nearby bugs",
          longDescription:
            "<p>Standard defender, it will sting nearby bugs.</p><p>This unit makes up for its lack of special ability by being fast and efficient.</p>",
          unlocksAtRound: -1,
          attackRank: 1,
          speedRank: 4,
          rangeRank: 2,
          options: {
            attackPower: 1,
            attackDelay: 75,
            attackType: "normal",
            targettingRules: ["auto", "first", "nearest", "strongest", "weakest"],
            upgrades: [
              { key: "bee_atk_spd", name: "Faster Sting", description: "Increases the attack speed", cost: 120, active: !1 },
              { key: "bee_pierce", name: "Sweeping Sting", description: "Attacks pierce through to a nearby enemy", cost: 280, active: !1 },
              { key: "bee_atk_pow", name: "Sharper Sting", description: "Increases the attack power and can damage shielded enemies", cost: 560, active: !1 },
            ],
          },
          sight: { shape: "circle", radius: 160 },
        },
        honeybee: {
          key: "honeybee",
          name: "Honey Bee",
          cost: 180,
          texture: "honeybee",
          origin: { x: 0.5, y: 0.95 },
          attackOrigin: { x: 0.5, y: 0.35 },
          radius: 32,
          description: "Spits sticky honey on enemies, slowing them down",
          longDescription:
            "<p>Spits sticky honey on enemies, slowing them down.</p><p>This unit deals no damage, but can give other units the time to deal more damage.</p>",
          unlocksAtRound: -1,
          attackRank: 0,
          speedRank: 2,
          rangeRank: 2,
          options: {
            attackPower: 0,
            attackDelay: 220,
            attackType: "water",
            targettingRules: ["auto", "first", "nearest", "strongest", "weakest"],
            upgrades: [
              { key: "honey_speed", name: "Faster Reload", description: "Can spit honey faster than ever", cost: 100, active: !1 },
              { key: "honey_puddle", name: "Stickier Honey", description: "Honey splats slow down more enemies for longer", cost: 200, active: !1 },
              { key: "honey_acid", name: "Corrosive Honey", description: "Shielded enemies take slow damage", cost: 400, active: !1 },
            ],
          },
          sight: { shape: "circle", radius: 180 },
        },
        rangerbee: {
          key: "rangerbee",
          name: "Ranger Bee",
          cost: 360,
          texture: "rangerbee",
          origin: { x: 0.5, y: 0.9 },
          attackOrigin: { x: 0.5, y: 0.8 },
          radius: 32,
          description:
            "Long range stinger.\nCan see small enemies like Ants.",
          longDescription:
            "<p>Long range stinger.</p><p>This unit specialises in spotting small enemies like <strong>Ants</strong>.</p><p>It is much slower than the standard Bee, but its range allows it to follow enemies for longer.</p>",
          unlocksAtRound: 4,
          attackRank: 2,
          speedRank: 2,
          rangeRank: 3,
          options: {
            attackPower: 1,
            attackDelay: 130,
            attackType: "normal",
            targettingRules: ["auto", "first", "nearest", "strongest", "weakest"],
            upgrades: [
              { key: "ranger_range", name: "Longer Range", description: "Increase range to see more enemies", cost: 180, active: !1 },
              { key: "ranger_speed", name: "Faster Reload", description: "Increase attack speed", cost: 320, active: !1 },
              { key: "ranger_piercing", name: "Piercing Sting", description: "Attacks will pierce through shielded enemies and also damage nearby enemies", cost: 640, active: !1 },
            ],
          },
          sight: { shape: "circle", radius: 220, canSeeSmall: !0 },
        },
        spikebee: {
          key: "spikebee",
          name: "Spike Bee",
          cost: 360,
          texture: "spikebee",
          origin: { x: 0.5, y: 0.5 },
          attackOrigin: { x: 0.5, y: 0.5 },
          radius: 32,
          description:
            "Short range, will sting all enemies nearby at once.\nCan damage shielded enemies",
          longDescription:
            "<p>Short range defender which can sting multiple enemies at once.</p><p>This unit specialises in damaging <strong>shielded enemies</strong>.</p>",
          unlocksAtRound: 8,
          attackRank: 3,
          speedRank: 2,
          rangeRank: 1,
          options: {
            attackPower: 1,
            attackDelay: 180,
            attackType: "piercing",
            targettingRules: [],
            upgrades: [
              { key: "spike_speed", name: "Faster Sting", description: "Attack speed increases", cost: 180, active: !1 },
              { key: "spike_spin", name: "Spin Attack", description: "Spins spikes around to hit more enemies", cost: 320, active: !1 },
              { key: "spike_sharp", name: "Sharper Spikes", description: "Spikes deal more damage", cost: 640, active: !1 },
            ],
          },
          sight: { shape: "circle", radius: 80 },
        },
        bombus: {
          key: "bombus",
          name: "Bombus Bee",
          cost: 480,
          texture: "bombus",
          origin: { x: 0.5, y: 0.8 },
          attackOrigin: { x: 0.2, y: 0.3 },
          radius: 50,
          description:
            "Launches an explosive at a single area, deals massive damage to all enemies in range. Can damage shielded enemies.",
          longDescription:
            "<p>Launches an explosive at a single area, deals massive damage to all enemies in range.</p><p>You can move this unit's target by tapping it and dragging the crosshair.</p>",
          unlocksAtRound: 15,
          attackRank: 3,
          speedRank: 1,
          rangeRank: 4,
          options: {
            attackPower: 1,
            attackDelay: 460,
            attackType: "normal",
            targettingRules: [],
            upgrades: [
              { key: "bombus_radius", name: "Bigger Explosion", description: "Creates a bigger explosion and damages more enemies", cost: 230, active: !1 },
              { key: "bombus_speed", name: "Faster Reload", description: "Fires bombs more regularly", cost: 460, active: !1 },
              { key: "bombus_shockwave", name: "Shockwave", description: "Explosions create a shockwave which blows enemies backwards", cost: 900, active: !1 },
            ],
          },
          sight: { shape: "circle", radius: 80, canBeMoved: !0 },
        },
        dewbee: {
          key: "dewbee",
          name: "Splash Bee",
          cost: 320,
          texture: "dewbee",
          origin: { x: 0.5, y: 1 },
          attackOrigin: { x: 0.4, y: 0.8 },
          radius: 32,
          description: "Throws water drops at enemies, pushing them back. Deals small damage to fiery enemies.",
          longDescription:
            "<p>Throws water drops at enemies, pushing them back.</p><p>This unit does not deal damage except to <strong>fiery enemies</strong>.</p>\n<p>Especially effective at slowing down <strong>Bears</strong> and keeping enemies in a crossfire for longer.</p>",
          unlocksAtRound: 25,
          attackRank: 0,
          speedRank: 2,
          rangeRank: 2,
          options: {
            attackPower: 0,
            attackDelay: 250,
            attackType: "water",
            targettingRules: ["auto", "first", "nearest", "strongest", "weakest"],
            upgrades: [
              { key: "dew_splash", name: "Bigger Splash", description: "Water drops make a bigger splash to knock more enemies back", cost: 160, active: !1 },
              { key: "dew_speed", name: "Faster Reload", description: "Throws water more often", cost: 320, active: !1 },
              { key: "dew_mist", name: "Misty Cloud", description: "Water splashes leave behind a cloud of mist which damages fiery enemies", cost: 620, active: !1 },
            ],
          },
          sight: { shape: "circle", radius: 160, seeksFire: !0 },
        },
        pepperbee: {
          key: "pepperbee",
          name: "Pepper Bee",
          cost: 500,
          texture: "pepperbee",
          origin: { x: 0.5, y: 0.95 },
          attackOrigin: { x: 0.5, y: 0.8 },
          radius: 32,
          unlocksAtRound: 35,
          attackRank: 2,
          speedRank: 3,
          rangeRank: 2,
          description: "A spicy bee with the power of fire! Leaves a lasting burn on enemies and deals extra damage to icy enemies.",
          longDescription:
            "<p>A spicy bee with the power of fire!</p><p>This unit leaves a lasting burn on enemies and deals extra damage to <strong>icy enemies</strong>.</p>",
          options: {
            attackPower: 1,
            attackDelay: 90,
            attackType: "fire",
            targettingRules: ["auto", "first", "nearest", "strongest", "weakest"],
            upgrades: [
              { key: "pepper_speed", name: "Faster Sting", description: "Increases attack speed", cost: 250, active: !1 },
              { key: "pepper_burn", name: "Blast Burn", description: "Stings burn nearby enemies", cost: 480, active: !1 },
              { key: "pepper_time", name: "Longer Burn", description: "Enemies burn for a longer time", cost: 800, active: !1 },
            ],
          },
          sight: { shape: "circle", radius: 150, seeksIce: !0 },
        },
        freezebee: {
          key: "freezebee",
          name: "Freeze Bee",
          cost: 500,
          texture: "freezebee",
          origin: { x: 0.5, y: 1 },
          attackOrigin: { x: 0.5, y: 0.7 },
          radius: 32,
          description: "A chilly bee with the power of ice! Slows enemies down and deals extra damage to fiery enemies.",
          longDescription:
            "<p>A chilly bee with the power of ice!</p><p>This unit slows enemies down and deals extra damage to <strong>fiery enemies</strong>.</p>",
          unlocksAtRound: 45,
          attackRank: 2,
          speedRank: 3,
          rangeRank: 2,
          options: {
            attackPower: 1,
            attackDelay: 90,
            attackType: "ice",
            targettingRules: ["auto", "first", "nearest", "strongest", "weakest"],
            upgrades: [
              { key: "freeze_speed", name: "Faster Sting", description: "Increases attack speed", cost: 250, active: !1 },
              { key: "freeze_burn", name: "Blast Freeze", description: "Stings slow down nearby enemies", cost: 480, active: !1 },
              { key: "freeze_time", name: "Deep Freeze", description: "Enemies are slower for a longer time", cost: 800, active: !1 },
            ],
          },
          sight: { shape: "circle", radius: 150, seeksFire: !0 },
        },
        royalguard: {
          key: "royalguard",
          name: "Royal Guard",
          cost: 700,
          texture: "royalguard",
          origin: { x: 0.5, y: 1 },
          attackOrigin: { x: 0.5, y: 0.5 },
          radius: 32,
          description: "Can only be placed by the gate. Deals massive damage to anything attacking the gate.",
          longDescription:
            "<p>Deals massive damage to anything attacking the gate.</p><p>This unit can only be placed on either side of the gate.</p><p>It is very effective at dealing with <strong>Worms</strong> and other enemies that slip past your other units.</p>",
          unlocksAtRound: 50,
          attackRank: 4,
          speedRank: 2,
          rangeRank: 1,
          options: {
            attackPower: 5,
            attackDelay: 140,
            attackType: "piercing",
            targettingRules: ["auto", "strongest", "weakest"],
            upgrades: [
              { key: "royal_knockback", name: "Guard's Vim", description: "Stings knock enemies away from the gate", cost: 360, active: !1 },
              { key: "royal_speed", name: "Guard's Vigour", description: "Increases attack speed", cost: 640, active: !1 },
              { key: "royal_pierce", name: "Guard's Valour", description: "Attacks pierce through to a nearby enemy", cost: 1200, active: !1 },
            ],
          },
          sight: { shape: "circle", radius: 120, canSeeSmall: !0 },
        },
        flower: {
          key: "flower",
          name: "Dandelion",
          cost: 400,
          texture: "flower",
          origin: { x: 0.5, y: 0.95 },
          attackOrigin: { x: 0.5, y: 0.5 },
          radius: 32,
          description: "Produces extra nectar at the end of each round",
          longDescription:
            "<p>Produces <strong>extra nectar</strong> at the end of each round.</p><p>This unit does not attack or interact with enemies.</p>",
          unlocksAtRound: 55,
          attackRank: 0,
          speedRank: 0,
          rangeRank: 0,
          options: {
            attackPower: 0,
            attackDelay: -1,
            attackType: "normal",
            targettingRules: [],
            upgrades: [
              { key: "flower_buff", name: "More Nectar", description: "More nectar is produced at the end of each round", cost: 200, active: !1 },
              { key: "flower_buffer", name: "Even More Nectar", description: "Even more nectar is produced at the end of each round", cost: 400, active: !1 },
              { key: "flower_buffest", name: "Again Even More Nectar", description: "Again, even more nectar is produced at the end of each round", cost: 800, active: !1 },
            ],
          },
        },
      };
    },
  },
]);

//# sourceMappingURL=4547.ee558c8c.js.map
