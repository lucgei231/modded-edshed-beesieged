(self["webpackChunkgame"] = self["webpackChunkgame"] || []).push([
  [764],
  {
    70913: function (t, e, i) {
      "use strict";
      i.d(e, {
        A: function () {
          return p;
        },
      });
      var n = function () {
          var t = this,
            e = t.$createElement,
            i = t._self._c || e;
          return t.open
            ? i(
                "div",
                { staticClass: "modal", class: { "is-active": t.open } },
                [
                  i("div", {
                    staticClass: "modal-background",
                    on: { click: t.close },
                  }),
                  i(
                    "div",
                    {
                      staticClass: "modal-card",
                      class: { "is-large": t.large, "is-medium": t.medium },
                    },
                    [
                      i("header", { staticClass: "modal-card-head" }, [
                        i("p", { staticClass: "modal-card-title" }, [
                          t._v(" " + t._s(t.title) + " "),
                        ]),
                        i("button", {
                          staticClass: "delete",
                          attrs: { "aria-label": "close" },
                          on: { click: t.close },
                        }),
                      ]),
                      i(
                        "section",
                        { staticClass: "modal-card-body" },
                        [t._t("default")],
                        2,
                      ),
                    ],
                  ),
                ],
              )
            : t._e();
        },
        s = [],
        r = i(91114),
        o = (i(62953), i(31635)),
        a = i(18657),
        l = i(53235);
      let u = class extends (0, a.Xe)(l.A) {
        constructor(...t) {
          (super(...t),
            (0, r.A)(this, "open", void 0),
            (0, r.A)(this, "large", void 0),
            (0, r.A)(this, "medium", void 0),
            (0, r.A)(this, "title", void 0),
            (0, r.A)(this, "closeWarning", void 0));
        }
        async closeModal() {
          this.closeWarning
            ? (await this.confirm({
                title: "Warning",
                message: "Do you wish to exit this form?",
              })) && this.close()
            : this.close();
        }
        close() {
          this.$emit("close");
        }
      };
      ((0, o.Cg)([(0, a.kv)({ default: !1 })], u.prototype, "open", void 0),
        (0, o.Cg)([(0, a.kv)({ type: Boolean })], u.prototype, "large", void 0),
        (0, o.Cg)(
          [(0, a.kv)({ type: Boolean })],
          u.prototype,
          "medium",
          void 0,
        ),
        (0, o.Cg)([(0, a.kv)({ default: "" })], u.prototype, "title", void 0),
        (0, o.Cg)(
          [(0, a.kv)({ type: Boolean })],
          u.prototype,
          "closeWarning",
          void 0,
        ),
        (u = (0, o.Cg)([(0, a.uA)({})], u)));
      var c = u,
        d = c,
        f = i(81656),
        h = (0, f.A)(d, n, s, !1, null, "a3995d78", null),
        p = h.exports;
    },
    73040: function (t, e, i) {
      !(function (e, n) {
        t.exports = n(i(85471));
      })(0, function (t) {
        return (function (t) {
          function e(n) {
            if (i[n]) return i[n].exports;
            var s = (i[n] = { i: n, l: !1, exports: {} });
            return (
              t[n].call(s.exports, s, s.exports, e),
              (s.l = !0),
              s.exports
            );
          }
          var i = {};
          return (
            (e.m = t),
            (e.c = i),
            (e.d = function (t, i, n) {
              e.o(t, i) ||
                Object.defineProperty(t, i, {
                  configurable: !1,
                  enumerable: !0,
                  get: n,
                });
            }),
            (e.n = function (t) {
              var i =
                t && t.__esModule
                  ? function () {
                      return t.default;
                    }
                  : function () {
                      return t;
                    };
              return (e.d(i, "a", i), i);
            }),
            (e.o = function (t, e) {
              return Object.prototype.hasOwnProperty.call(t, e);
            }),
            (e.p = "/dist/"),
            e((e.s = 10))
          );
        })([
          function (t, e) {
            t.exports = function (t, e, i, n) {
              var s,
                r = (t = t || {}),
                o = typeof t.default;
              ("object" !== o && "function" !== o) ||
                ((s = t), (r = t.default));
              var a = "function" == typeof r ? r.options : r;
              if (
                (e &&
                  ((a.render = e.render),
                  (a.staticRenderFns = e.staticRenderFns)),
                i && (a._scopeId = i),
                n)
              ) {
                var l = Object.create(a.computed || null);
                (Object.keys(n).forEach(function (t) {
                  var e = n[t];
                  l[t] = function () {
                    return e;
                  };
                }),
                  (a.computed = l));
              }
              return { esModule: s, exports: r, options: a };
            };
          },
          function (t, e, i) {
            i(13);
            var n = i(0)(i(16), i(17), "data-v-217e3916", null);
            t.exports = n.exports;
          },
          function (e, i) {
            e.exports = t;
          },
          function (t, e, i) {
            "use strict";
            (Object.defineProperty(e, "__esModule", { value: !0 }),
              (e.default = {
                props: {
                  fill: { type: Number, default: 0 },
                  size: { type: Number, default: 50 },
                  index: { type: Number, required: !0 },
                  activeColor: { type: String, required: !0 },
                  inactiveColor: { type: String, required: !0 },
                  borderColor: { type: String, default: "#999" },
                  borderWidth: { type: Number, default: 0 },
                  spacing: { type: Number, default: 0 },
                  customProps: {
                    type: Object,
                    default: function () {
                      return {};
                    },
                  },
                  rtl: { type: Boolean, default: !1 },
                },
                created: function () {
                  this.fillId = Math.random().toString(36).substring(7);
                },
                computed: {
                  pointsToString: function () {
                    return this.points.join(",");
                  },
                  getFillId: function () {
                    return "url(#" + this.fillId + ")";
                  },
                  getWidth: function () {
                    return (
                      parseInt(this.size) +
                      parseInt(this.borderWidth * this.borders)
                    );
                  },
                  getHeight: function () {
                    return (
                      (this.originalHeight / this.originalWidth) * this.getWidth
                    );
                  },
                  getFill: function () {
                    return this.rtl ? 100 - this.fill + "%" : this.fill + "%";
                  },
                  getSpacing: function () {
                    return this.spacing + this.borderWidth / 2 + "px";
                  },
                },
                methods: {
                  mouseMoving: function (t) {
                    this.$emit("mouse-move", {
                      event: t,
                      position: this.getPosition(t),
                      id: this.index,
                    });
                  },
                  getPosition: function (t) {
                    var e = 0.92 * (this.size + this.borderWidth),
                      i = this.rtl
                        ? Math.min(t.offsetX, 45)
                        : Math.max(t.offsetX, 1),
                      n = Math.round((100 / e) * i);
                    return Math.min(n, 100);
                  },
                  selected: function (t) {
                    this.$emit("selected", {
                      id: this.index,
                      position: this.getPosition(t),
                    });
                  },
                },
                data: function () {
                  return {
                    fillId: "",
                    originalWidth: 50,
                    orignalHeight: 50,
                    borders: 1,
                  };
                },
              }));
          },
          function (t, e) {
            t.exports = function () {
              var t = [];
              return (
                (t.toString = function () {
                  for (var t = [], e = 0; e < this.length; e++) {
                    var i = this[e];
                    i[2]
                      ? t.push("@media " + i[2] + "{" + i[1] + "}")
                      : t.push(i[1]);
                  }
                  return t.join("");
                }),
                (t.i = function (e, i) {
                  "string" == typeof e && (e = [[null, e, ""]]);
                  for (var n = {}, s = 0; s < this.length; s++) {
                    var r = this[s][0];
                    "number" == typeof r && (n[r] = !0);
                  }
                  for (s = 0; s < e.length; s++) {
                    var o = e[s];
                    ("number" == typeof o[0] && n[o[0]]) ||
                      (i && !o[2]
                        ? (o[2] = i)
                        : i && (o[2] = "(" + o[2] + ") and (" + i + ")"),
                      t.push(o));
                  }
                }),
                t
              );
            };
          },
          function (t, e, i) {
            function n(t) {
              for (var e = 0; e < t.length; e++) {
                var i = t[e],
                  n = c[i.id];
                if (n) {
                  n.refs++;
                  for (var s = 0; s < n.parts.length; s++)
                    n.parts[s](i.parts[s]);
                  for (; s < i.parts.length; s++) n.parts.push(r(i.parts[s]));
                  n.parts.length > i.parts.length &&
                    (n.parts.length = i.parts.length);
                } else {
                  var o = [];
                  for (s = 0; s < i.parts.length; s++) o.push(r(i.parts[s]));
                  c[i.id] = { id: i.id, refs: 1, parts: o };
                }
              }
            }
            function s() {
              var t = document.createElement("style");
              return ((t.type = "text/css"), d.appendChild(t), t);
            }
            function r(t) {
              var e,
                i,
                n = document.querySelector(
                  'style[data-vue-ssr-id~="' + t.id + '"]',
                );
              if (n) {
                if (p) return g;
                n.parentNode.removeChild(n);
              }
              if (m) {
                var r = h++;
                ((n = f || (f = s())),
                  (e = o.bind(null, n, r, !1)),
                  (i = o.bind(null, n, r, !0)));
              } else
                ((n = s()),
                  (e = a.bind(null, n)),
                  (i = function () {
                    n.parentNode.removeChild(n);
                  }));
              return (
                e(t),
                function (n) {
                  if (n) {
                    if (
                      n.css === t.css &&
                      n.media === t.media &&
                      n.sourceMap === t.sourceMap
                    )
                      return;
                    e((t = n));
                  } else i();
                }
              );
            }
            function o(t, e, i, n) {
              var s = i ? "" : n.css;
              if (t.styleSheet) t.styleSheet.cssText = v(e, s);
              else {
                var r = document.createTextNode(s),
                  o = t.childNodes;
                (o[e] && t.removeChild(o[e]),
                  o.length ? t.insertBefore(r, o[e]) : t.appendChild(r));
              }
            }
            function a(t, e) {
              var i = e.css,
                n = e.media,
                s = e.sourceMap;
              if (
                (n && t.setAttribute("media", n),
                s &&
                  ((i += "\n/*# sourceURL=" + s.sources[0] + " */"),
                  (i +=
                    "\n/*# sourceMappingURL=data:application/json;base64," +
                    btoa(unescape(encodeURIComponent(JSON.stringify(s)))) +
                    " */")),
                t.styleSheet)
              )
                t.styleSheet.cssText = i;
              else {
                for (; t.firstChild; ) t.removeChild(t.firstChild);
                t.appendChild(document.createTextNode(i));
              }
            }
            var l = "undefined" != typeof document;
            if ("undefined" != typeof DEBUG && DEBUG && !l)
              throw new Error(
                "vue-style-loader cannot be used in a non-browser environment. Use { target: 'node' } in your Webpack config to indicate a server-rendering environment.",
              );
            var u = i(15),
              c = {},
              d =
                l &&
                (document.head || document.getElementsByTagName("head")[0]),
              f = null,
              h = 0,
              p = !1,
              g = function () {},
              m =
                "undefined" != typeof navigator &&
                /msie [6-9]\b/.test(navigator.userAgent.toLowerCase());
            t.exports = function (t, e, i) {
              p = i;
              var s = u(t, e);
              return (
                n(s),
                function (e) {
                  for (var i = [], r = 0; r < s.length; r++) {
                    var o = s[r],
                      a = c[o.id];
                    (a.refs--, i.push(a));
                  }
                  e ? ((s = u(t, e)), n(s)) : (s = []);
                  for (r = 0; r < i.length; r++) {
                    a = i[r];
                    if (0 === a.refs) {
                      for (var l = 0; l < a.parts.length; l++) a.parts[l]();
                      delete c[a.id];
                    }
                  }
                }
              );
            };
            var v = (function () {
              var t = [];
              return function (e, i) {
                return ((t[e] = i), t.filter(Boolean).join("\n"));
              };
            })();
          },
          function (t, e, i) {
            var n = i(0)(i(28), i(29), null, null);
            t.exports = n.exports;
          },
          function (t, e, i) {
            "use strict";
            (Object.defineProperty(e, "__esModule", { value: !0 }),
              (e.default = {
                props: {
                  increment: { type: Number, default: 1 },
                  rating: { type: Number, default: 0 },
                  activeColor: { type: String, default: "#ffd055" },
                  inactiveColor: { type: String, default: "#d8d8d8" },
                  maxRating: { type: Number, default: 5 },
                  itemSize: { type: Number, default: 50 },
                  showRating: { type: Boolean, default: !0 },
                  readOnly: { type: Boolean, default: !1 },
                  textClass: { type: String, default: "" },
                  inline: { type: Boolean, default: !1 },
                  borderColor: { type: String, default: "#999" },
                  borderWidth: { type: Number, default: 2 },
                  spacing: { type: Number, default: 0 },
                  fixedPoints: { type: Number, default: null },
                  rtl: { type: Boolean, default: !1 },
                },
                model: { prop: "rating", event: "rating-selected" },
                created: function () {
                  ((this.step = 100 * this.increment),
                    (this.currentRating = this.rating),
                    (this.selectedRating = this.rating),
                    this.createRating());
                },
                methods: {
                  setRating: function (t, e) {
                    if (!this.readOnly) {
                      var i = this.rtl
                        ? (100 - t.position) / 100
                        : t.position / 100;
                      ((this.currentRating = (t.id + i - 1).toFixed(2)),
                        (this.currentRating =
                          this.currentRating > this.maxRating
                            ? this.maxRating
                            : this.currentRating),
                        this.createRating(),
                        e
                          ? ((this.selectedRating = this.currentRating),
                            this.$emit("rating-selected", this.selectedRating))
                          : this.$emit("current-rating", this.currentRating));
                    }
                  },
                  resetRating: function () {
                    this.readOnly ||
                      ((this.currentRating = this.selectedRating),
                      this.createRating());
                  },
                  createRating: function () {
                    this.round();
                    for (var t = 0; t < this.maxRating; t++) {
                      var e = 0;
                      (t < this.currentRating &&
                        (e =
                          this.currentRating - t > 1
                            ? 100
                            : 100 * (this.currentRating - t)),
                        this.$set(this.fillLevel, t, Math.round(e)));
                    }
                  },
                  round: function () {
                    var t = 1 / this.increment;
                    this.currentRating = Math.min(
                      this.maxRating,
                      Math.ceil(this.currentRating * t) / t,
                    );
                  },
                },
                computed: {
                  formattedRating: function () {
                    return null === this.fixedPoints
                      ? this.currentRating
                      : this.currentRating.toFixed(this.fixedPoints);
                  },
                },
                watch: {
                  rating: function (t) {
                    ((this.currentRating = t),
                      (this.selectedRating = t),
                      this.createRating());
                  },
                },
                data: function () {
                  return {
                    step: 0,
                    fillLevel: [],
                    currentRating: 0,
                    selectedRating: 0,
                    customProps: {},
                  };
                },
              }));
          },
          function (t, e, i) {
            var n = i(0)(i(20), i(21), null, null);
            t.exports = n.exports;
          },
          function (t, e, i) {
            i(34);
            var n = i(0)(i(36), null, null, null);
            t.exports = n.exports;
          },
          function (t, e, i) {
            "use strict";
            function n(t) {
              return t && t.__esModule ? t : { default: t };
            }
            (Object.defineProperty(e, "__esModule", { value: !0 }),
              (e.Polygon =
                e.Path =
                e.RateIt =
                e.FaBaseGlyph =
                e.BaseRating =
                e.ImageRating =
                e.FaRating =
                e.HeartRating =
                e.StarRating =
                e.mixins =
                  void 0));
            var s = i(11),
              r = n(s),
              o = i(22),
              a = n(o),
              l = i(30),
              u = n(l),
              c = i(37),
              d = n(c),
              f = i(1),
              h = n(f),
              p = i(42),
              g = n(p),
              m = i(44),
              v = n(m),
              y = i(9),
              _ = n(y),
              b = i(6),
              x = n(b),
              C = i(8),
              S = n(C),
              R = {
                StarRating: r.default,
                HeartRating: a.default,
                FaRating: u.default,
                ImageRating: d.default,
              };
            ((e.default = R),
              (e.mixins = v.default),
              (e.StarRating = r.default),
              (e.HeartRating = a.default),
              (e.FaRating = u.default),
              (e.ImageRating = d.default),
              (e.BaseRating = h.default),
              (e.FaBaseGlyph = _.default),
              (e.RateIt = g.default),
              (e.Path = x.default),
              (e.Polygon = S.default));
          },
          function (t, e, i) {
            var n = i(0)(i(12), null, null, null);
            t.exports = n.exports;
          },
          function (t, e, i) {
            "use strict";
            function n(t) {
              return t && t.__esModule ? t : { default: t };
            }
            Object.defineProperty(e, "__esModule", { value: !0 });
            var s = i(1),
              r = n(s),
              o = i(18),
              a = n(o);
            e.default = r.default.extend({
              name: "Star-Rating",
              components: { Star: a.default },
              data: function () {
                return { type: "star" };
              },
            });
          },
          function (t, e, i) {
            var n = i(14);
            ("string" == typeof n && (n = [[t.i, n, ""]]),
              n.locals && (t.exports = n.locals),
              i(5)("77372b13", n, !0));
          },
          function (t, e, i) {
            ((e = t.exports = i(4)()),
              e.push([
                t.i,
                ".vue-rate-it-rating-item[data-v-217e3916]{display:inline-block}.vue-rate-it-pointer[data-v-217e3916]{cursor:pointer}.vue-rate-it-rating[data-v-217e3916]{display:flex;align-items:center}.vue-rate-it-inline[data-v-217e3916]{display:inline-flex}.vue-rate-it-rating-text[data-v-217e3916]{margin-top:7px;margin-left:7px}.vue-rate-it-rtl[data-v-217e3916]{direction:rtl}.vue-rate-it-rtl .vue-rate-it-rating-text[data-v-217e3916]{margin-right:10px;direction:rtl}",
                "",
              ]));
          },
          function (t, e) {
            t.exports = function (t, e) {
              for (var i = [], n = {}, s = 0; s < e.length; s++) {
                var r = e[s],
                  o = r[0],
                  a = r[1],
                  l = r[2],
                  u = r[3],
                  c = { id: t + ":" + s, css: a, media: l, sourceMap: u };
                n[o]
                  ? n[o].parts.push(c)
                  : i.push((n[o] = { id: o, parts: [c] }));
              }
              return i;
            };
          },
          function (t, e, i) {
            "use strict";
            function n(t) {
              return t && t.__esModule ? t : { default: t };
            }
            Object.defineProperty(e, "__esModule", { value: !0 });
            var s = i(2),
              r = n(s),
              o = i(7),
              a = n(o);
            e.default = r.default.extend({
              mixins: [a.default],
              data: function () {
                return { type: "" };
              },
            });
          },
          function (t, e) {
            t.exports = {
              render: function () {
                var t = this,
                  e = t.$createElement,
                  i = t._self._c || e;
                return i(
                  "div",
                  {
                    class: [
                      "vue-rate-it-rating",
                      { "vue-rate-it-rtl": t.rtl },
                      { "vue-rate-it-inline": t.inline },
                      "vue-rate-it-rating-container",
                    ],
                  },
                  [
                    i(
                      "div",
                      {
                        staticClass: "vue-rate-it-rating",
                        on: { mouseleave: t.resetRating },
                      },
                      [
                        t._l(t.maxRating, function (e) {
                          return i(
                            "div",
                            {
                              class: [
                                { "vue-rate-it-pointer": !t.readOnly },
                                "vue-rate-it-rating-item",
                              ],
                            },
                            [
                              i(t.type, {
                                tag: "component",
                                attrs: {
                                  fill: t.fillLevel[e - 1],
                                  size: t.itemSize,
                                  index: e,
                                  step: t.step,
                                  "active-color": t.activeColor,
                                  "inactive-color": t.inactiveColor,
                                  "border-color": t.borderColor,
                                  "border-width": t.borderWidth,
                                  spacing: t.spacing,
                                  "custom-props": t.customProps,
                                  rtl: t.rtl,
                                },
                                on: {
                                  selected: function (e) {
                                    t.setRating(e, !0);
                                  },
                                  "mouse-move": t.setRating,
                                },
                              }),
                            ],
                            1,
                          );
                        }),
                        t._v(" "),
                        t.showRating
                          ? i(
                              "span",
                              {
                                class: ["vue-rate-it-rating-text", t.textClass],
                              },
                              [t._v(" " + t._s(t.formattedRating))],
                            )
                          : t._e(),
                      ],
                      2,
                    ),
                  ],
                );
              },
              staticRenderFns: [],
            };
          },
          function (t, e, i) {
            var n = i(0)(i(19), null, null, null);
            t.exports = n.exports;
          },
          function (t, e, i) {
            "use strict";
            Object.defineProperty(e, "__esModule", { value: !0 });
            var n = i(8),
              s = (function (t) {
                return t && t.__esModule ? t : { default: t };
              })(n);
            e.default = s.default.extend({
              data: function () {
                return {
                  points: [
                    19.8, 2.2, 6.6, 43.56, 39.6, 17.16, 0, 17.16, 33, 43.56,
                  ],
                  originalWidth: 43,
                  originalHeight: 43,
                  borders: 3,
                };
              },
            });
          },
          function (t, e, i) {
            "use strict";
            function n(t) {
              return t && t.__esModule ? t : { default: t };
            }
            Object.defineProperty(e, "__esModule", { value: !0 });
            var s = i(2),
              r = n(s),
              o = i(3),
              a = n(o);
            e.default = r.default.extend({
              mixins: [a.default],
              created: function () {
                this.calculatePoints();
              },
              methods: {
                calculatePoints: function () {
                  var t = this;
                  this.points = this.points.map(function (e) {
                    return (
                      (t.size / t.originalWidth) * e +
                      t.borderWidth * (t.borders / 2)
                    );
                  });
                },
              },
              data: function () {
                return { points: [] };
              },
            });
          },
          function (t, e) {
            t.exports = {
              render: function () {
                var t = this,
                  e = t.$createElement,
                  i = t._self._c || e;
                return i(
                  "svg",
                  {
                    staticStyle: { overflow: "visible" },
                    attrs: { width: t.getWidth, height: t.getHeight },
                    on: { mousemove: t.mouseMoving, click: t.selected },
                  },
                  [
                    i(
                      "linearGradient",
                      {
                        attrs: {
                          id: t.fillId,
                          x1: "0",
                          x2: "100%",
                          y1: "0",
                          y2: "0",
                        },
                      },
                      [
                        i("stop", {
                          attrs: {
                            offset: t.getFill,
                            "stop-color": t.rtl
                              ? t.inactiveColor
                              : t.activeColor,
                          },
                        }),
                        t._v(" "),
                        i("stop", {
                          attrs: {
                            offset: t.getFill,
                            "stop-color": t.rtl
                              ? t.activeColor
                              : t.inactiveColor,
                          },
                        }),
                      ],
                      1,
                    ),
                    t._v(" "),
                    i("polygon", {
                      attrs: {
                        points: t.pointsToString,
                        fill: t.getFillId,
                        stroke: t.borderColor,
                        "stroke-width": t.borderWidth,
                      },
                    }),
                    t._v(" "),
                    i("polygon", {
                      attrs: { points: t.pointsToString, fill: t.getFillId },
                    }),
                  ],
                  1,
                );
              },
              staticRenderFns: [],
            };
          },
          function (t, e, i) {
            i(23);
            var n = i(0)(i(25), null, null, null);
            t.exports = n.exports;
          },
          function (t, e, i) {
            var n = i(24);
            ("string" == typeof n && (n = [[t.i, n, ""]]),
              n.locals && (t.exports = n.locals),
              i(5)("2494179e", n, !0));
          },
          function (t, e, i) {
            ((e = t.exports = i(4)()),
              e.push([
                t.i,
                ".rating-container.inline{display:inline-flex;margin-left:5px;margin-right:1px}",
                "",
              ]));
          },
          function (t, e, i) {
            "use strict";
            function n(t) {
              return t && t.__esModule ? t : { default: t };
            }
            Object.defineProperty(e, "__esModule", { value: !0 });
            var s = i(1),
              r = n(s),
              o = i(26),
              a = n(o);
            e.default = r.default.extend({
              name: "Heart-Rating",
              components: { Heart: a.default },
              props: {
                borderWidth: { type: Number, default: 3 },
                activeColor: { type: String, default: "#d80000" },
                inactiveColor: { type: String, default: "#ffc4c4" },
                borderColor: { type: String, default: "#8b0000" },
              },
              data: function () {
                return { type: "heart" };
              },
            });
          },
          function (t, e, i) {
            var n = i(0)(i(27), null, null, null);
            t.exports = n.exports;
          },
          function (t, e, i) {
            "use strict";
            Object.defineProperty(e, "__esModule", { value: !0 });
            var n = i(6),
              s = (function (t) {
                return t && t.__esModule ? t : { default: t };
              })(n);
            e.default = s.default.extend({
              data: function () {
                return {
                  points: [
                    "M 297.29747 550.86823 C 283.52243 535.43191 249.1268 505.33855 220.86277 483.99412 C 137.11867 420.75228 125.72108 411.5999 91.719238 380.29088 C 29.03471 322.57071 2.413622 264.58086 2.5048478 185.95124 C 2.5493594 147.56739 5.1656152 132.77929 15.914734 110.15398 C 34.151433 71.768267 61.014996 43.244667 95.360052 25.799457 C 119.68545 13.443675 131.6827 7.9542046 172.30448 7.7296236 C 214.79777 7.4947896 223.74311 12.449347 248.73919 26.181459 C 279.1637 42.895777 310.47909 78.617167 316.95242 103.99205 L 320.95052 119.66445 L 330.81015 98.079942 C 386.52632 -23.892986 564.40851 -22.06811 626.31244 101.11153 C 645.95011 140.18758 648.10608 223.6247 630.69256 270.6244 C 607.97729 331.93377 565.31255 378.67493 466.68622 450.30098 C 402.0054 497.27462 328.80148 568.34684 323.70555 578.32901 C 317.79007 589.91654 323.42339 580.14491 297.29747 550.86823 z",
                  ],
                  originalWidth: 700,
                  originalHeight: 565,
                };
              },
            });
          },
          function (t, e, i) {
            "use strict";
            function n(t) {
              return t && t.__esModule ? t : { default: t };
            }
            Object.defineProperty(e, "__esModule", { value: !0 });
            var s = i(2),
              r = n(s),
              o = i(3),
              a = n(o);
            e.default = r.default.extend({
              mixins: [a.default],
              computed: {
                getViewbox: function () {
                  return (
                    "0 0 " + this.originalWidth + " " + this.originalHeight
                  );
                },
                getFill: function () {
                  var t = (this.fill / 100) * Math.abs(this.x1Val),
                    e = this.x1Val > 0 ? this.fill - t : this.fill + t;
                  return this.rtl ? 100 - e + "%" : e + "%";
                },
                x1Val: function () {
                  return parseInt(this.coords.x1.replace("%"));
                },
              },
              data: function () {
                return {
                  points: [],
                  pathAttrs: {},
                  coords: { x1: "0%", x2: "100%", y1: "0%", y2: "0%" },
                };
              },
            });
          },
          function (t, e) {
            t.exports = {
              render: function () {
                var t = this,
                  e = t.$createElement,
                  i = t._self._c || e;
                return i(
                  "div",
                  {
                    style: {
                      display: "inline-block",
                      "margin-right": t.getSpacing,
                    },
                  },
                  [
                    i(
                      "svg",
                      {
                        staticStyle: { overflow: "visible" },
                        attrs: {
                          width: t.getWidth,
                          height: t.getHeight,
                          viewBox: t.getViewbox,
                        },
                        on: { mousemove: t.mouseMoving, click: t.selected },
                      },
                      [
                        i(
                          "linearGradient",
                          t._b(
                            { attrs: { id: t.fillId } },
                            "linearGradient",
                            t.coords,
                            !1,
                          ),
                          [
                            i("stop", {
                              attrs: {
                                offset: t.getFill,
                                "stop-color": t.rtl
                                  ? t.inactiveColor
                                  : t.activeColor,
                              },
                            }),
                            t._v(" "),
                            i("stop", {
                              attrs: {
                                offset: t.getFill,
                                "stop-color": t.rtl
                                  ? t.activeColor
                                  : t.inactiveColor,
                              },
                            }),
                          ],
                          1,
                        ),
                        t._v(" "),
                        i(
                          "path",
                          t._b(
                            {
                              attrs: {
                                d: t.pointsToString,
                                fill: t.getFillId,
                                stroke: t.borderColor,
                                "stroke-width": t.borderWidth,
                                "vector-effect": "non-scaling-stroke",
                              },
                            },
                            "path",
                            t.pathAttrs,
                            !1,
                          ),
                        ),
                        t._v(" "),
                        i(
                          "path",
                          t._b(
                            {
                              attrs: { d: t.pointsToString, fill: t.getFillId },
                            },
                            "path",
                            t.pathAttrs,
                            !1,
                          ),
                        ),
                      ],
                      1,
                    ),
                  ],
                );
              },
              staticRenderFns: [],
            };
          },
          function (t, e, i) {
            var n = i(0)(i(31), null, null, null);
            t.exports = n.exports;
          },
          function (t, e, i) {
            "use strict";
            function n(t) {
              return t && t.__esModule ? t : { default: t };
            }
            Object.defineProperty(e, "__esModule", { value: !0 });
            var s = i(1),
              r = n(s),
              o = i(32),
              a = n(o);
            e.default = r.default.extend({
              name: "Fa-Rating",
              components: { FaGlyph: a.default },
              props: {
                glyph: { type: String, required: !0 },
                activeColor: { type: String, default: "#000" },
              },
              created: function () {
                this.customProps.glyph = this.glyph;
              },
              data: function () {
                return { type: "fa-glyph" };
              },
            });
          },
          function (t, e, i) {
            var n = i(0)(i(33), null, null, null);
            t.exports = n.exports;
          },
          function (t, e, i) {
            "use strict";
            Object.defineProperty(e, "__esModule", { value: !0 });
            var n = i(9),
              s = (function (t) {
                return t && t.__esModule ? t : { default: t };
              })(n);
            e.default = s.default.extend({
              created: function () {
                this.updateGlyph();
              },
              methods: {
                updateGlyph: function () {
                  this.points = [this.customProps.glyph];
                },
              },
            });
          },
          function (t, e, i) {
            var n = i(35);
            ("string" == typeof n && (n = [[t.i, n, ""]]),
              n.locals && (t.exports = n.locals),
              i(5)("62348d90", n, !0));
          },
          function (t, e, i) {
            ((e = t.exports = i(4)()),
              e.push([
                t.i,
                ".rating-container.inline{display:inline-flex;margin-left:5px;margin-right:1px}",
                "",
              ]));
          },
          function (t, e, i) {
            "use strict";
            Object.defineProperty(e, "__esModule", { value: !0 });
            var n = i(6),
              s = (function (t) {
                return t && t.__esModule ? t : { default: t };
              })(n);
            e.default = s.default.extend({
              props: { customProps: { required: !0, type: Object } },
              created: function () {
                this.coords.x1 = "-2%";
              },
              data: function () {
                return {
                  points: [],
                  originalWidth: 179,
                  originalHeight: 179,
                  pathAttrs: { transform: "scale(0.1)" },
                };
              },
            });
          },
          function (t, e, i) {
            var n = i(0)(i(38), null, null, null);
            t.exports = n.exports;
          },
          function (t, e, i) {
            "use strict";
            function n(t) {
              return t && t.__esModule ? t : { default: t };
            }
            Object.defineProperty(e, "__esModule", { value: !0 });
            var s = i(1),
              r = n(s),
              o = i(39),
              a = n(o);
            e.default = r.default.extend({
              name: "Image-Rating",
              props: {
                backgroundOpacity: { default: 0.2, type: Number },
                src: { type: String, required: !0 },
              },
              created: function () {
                ((this.customProps.opacity = this.backgroundOpacity),
                  (this.customProps.src = this.src));
              },
              components: { CImage: a.default },
              data: function () {
                return { type: "c-image" };
              },
            });
          },
          function (t, e, i) {
            var n = i(0)(i(40), i(41), null, null);
            t.exports = n.exports;
          },
          function (t, e, i) {
            "use strict";
            function n(t) {
              return t && t.__esModule ? t : { default: t };
            }
            Object.defineProperty(e, "__esModule", { value: !0 });
            var s = i(2),
              r = n(s),
              o = i(3),
              a = n(o);
            e.default = r.default.extend({
              mixins: [a.default],
              created: function () {
                var t = this;
                ((this.opacity = this.customProps.opacity),
                  (this.src = this.customProps.src));
                var e = new Image();
                ((e.onload = function () {
                  ((t.originalHeight = e.height), (t.originalWidth = e.width));
                }),
                  (e.src = this.src));
              },
              computed: {
                getOpacity: function () {
                  return "opacity:" + this.opacity;
                },
                getFill: function () {
                  return this.fill + "%";
                },
                getX: function () {
                  return this.rtl ? 100 - this.fill + "%" : 0;
                },
              },
              data: function () {
                return {
                  points: [],
                  originalWidth: 400,
                  originalHeight: 300,
                  borders: 0,
                  opacity: 0.1,
                };
              },
            });
          },
          function (t, e) {
            t.exports = {
              render: function () {
                var t = this,
                  e = t.$createElement,
                  i = t._self._c || e;
                return i(
                  "div",
                  {
                    style: {
                      display: "inline-block",
                      "margin-right": t.getSpacing,
                    },
                  },
                  [
                    i(
                      "svg",
                      {
                        attrs: { width: t.getWidth, height: t.getHeight },
                        on: { mousemove: t.mouseMoving, click: t.selected },
                      },
                      [
                        i("mask", { attrs: { x: "0", y: "0", id: t.fillId } }, [
                          i("rect", {
                            attrs: {
                              fill: "#fff",
                              width: t.getFill,
                              height: "100%",
                              x: t.getX,
                            },
                          }),
                        ]),
                        t._v(" "),
                        i("image", {
                          attrs: {
                            "xlink:href": t.src,
                            mask: t.getFillId,
                            height: t.getHeight,
                            width: t.getWidth,
                          },
                        }),
                        t._v(" "),
                        i("image", {
                          style: t.getOpacity,
                          attrs: {
                            "xlink:href": t.src,
                            height: t.getHeight,
                            width: t.getWidth,
                          },
                        }),
                      ],
                    ),
                  ],
                );
              },
              staticRenderFns: [],
            };
          },
          function (t, e, i) {
            var n = i(0)(i(43), null, null, null);
            t.exports = n.exports;
          },
          function (t, e, i) {
            "use strict";
            Object.defineProperty(e, "__esModule", { value: !0 });
            var n = i(1),
              s = (function (t) {
                return t && t.__esModule ? t : { default: t };
              })(n);
            e.default = s.default.extend({
              name: "rate-it",
              props: { with: { type: Function, required: !0 } },
              created: function () {
                void 0 !== this.with && (this.type = this.with);
              },
              watch: {
                with: function (t) {
                  this.type = t;
                },
              },
            });
          },
          function (t, e, i) {
            "use strict";
            function n(t) {
              return t && t.__esModule ? t : { default: t };
            }
            Object.defineProperty(e, "__esModule", { value: !0 });
            var s = i(7),
              r = n(s),
              o = i(3),
              a = n(o);
            e.default = { Rating: r.default, RatingItem: a.default };
          },
        ]);
      });
    },
    86567: function (t, e, i) {
      "use strict";
      i.d(e, {
        A: function () {
          return h;
        },
      });
      var n = function () {
          var t = this,
            e = t.$createElement,
            i = t._self._c || e;
          return i(
            "div",
            { staticClass: "modal is-active", attrs: { id: "resultModal" } },
            [
              i("div", {
                staticClass: "modal-background",
                on: {
                  click: function (e) {
                    return (e.preventDefault(), t.hideSettings(e));
                  },
                },
              }),
              i("div", { staticClass: "modal-content" }, [
                i("div", { attrs: { id: "settings-box" } }, [
                  t._m(0),
                  i("div", { staticClass: "content" }, [
                    t._m(1),
                    i("div", { staticClass: "setting" }, [
                      t._v(" Music "),
                      i(
                        "a",
                        {
                          attrs: { href: "#" },
                          on: {
                            click: function (e) {
                              return (e.preventDefault(), t.toggleMusic(e));
                            },
                          },
                        },
                        [
                          i("figure", { staticClass: "image" }, [
                            i("img", {
                              attrs: {
                                src:
                                  "/images/" +
                                  (t.musicOn
                                    ? "soundOnIcon.png"
                                    : "soundOffIcon.png"),
                              },
                            }),
                          ]),
                        ],
                      ),
                    ]),
                    i("div", { staticClass: "setting" }, [
                      t._v(" Sound FX "),
                      i(
                        "a",
                        {
                          attrs: { href: "#" },
                          on: {
                            click: function (e) {
                              return (e.preventDefault(), t.toggleSoundFX(e));
                            },
                          },
                        },
                        [
                          i("figure", { staticClass: "image" }, [
                            i("img", {
                              attrs: {
                                src:
                                  "/images/" +
                                  (t.soundFXOn
                                    ? "soundOnIcon.png"
                                    : "soundOffIcon.png"),
                              },
                            }),
                          ]),
                        ],
                      ),
                    ]),
                    t.number || "phonics" === t.location
                      ? t._e()
                      : i("div", { staticClass: "setting" }, [
                          t._v(" Letter Names "),
                          i(
                            "a",
                            {
                              attrs: { href: "#" },
                              on: {
                                click: function (e) {
                                  return (
                                    e.preventDefault(),
                                    t.toggleLetterNames(e)
                                  );
                                },
                              },
                            },
                            [
                              i("figure", { staticClass: "image" }, [
                                i("img", {
                                  attrs: {
                                    src:
                                      "/images/" +
                                      (t.letterNamesOn
                                        ? "soundOnIcon.png"
                                        : "soundOffIcon.png"),
                                  },
                                }),
                              ]),
                            ],
                          ),
                        ]),
                    t.pause
                      ? t._e()
                      : i("div", { staticClass: "setting" }, [
                          t._v(" Show Bonus Bar "),
                          i(
                            "a",
                            {
                              attrs: { href: "#" },
                              on: {
                                click: function (e) {
                                  return (
                                    e.preventDefault(),
                                    t.toggleTimers(e)
                                  );
                                },
                              },
                            },
                            [
                              i("figure", { staticClass: "image" }, [
                                i("img", {
                                  attrs: {
                                    src:
                                      "/images/" +
                                      (t.disableTimer
                                        ? "cross.png"
                                        : "tick.png"),
                                  },
                                }),
                              ]),
                            ],
                          ),
                        ]),
                    (t.pause && !t.number) || !t.allowInvertCalculator
                      ? t._e()
                      : i("div", { staticClass: "setting" }, [
                          t._v(" Invert Calculator "),
                          i(
                            "a",
                            {
                              staticClass: "has-text-dark",
                              attrs: { href: "#" },
                              on: {
                                click: function (e) {
                                  return (
                                    e.preventDefault(),
                                    t.toggleInvertCalc(e)
                                  );
                                },
                              },
                            },
                            [
                              i("figure", { staticClass: "image" }, [
                                t.invertCalcOn
                                  ? i("i", { staticClass: "mdi mdi-check" })
                                  : i("i", { staticClass: "mdi mdi-close" }),
                              ]),
                            ],
                          ),
                        ]),
                    !t.pause && t.canChangeFont
                      ? i(
                          "div",
                          { staticClass: "setting" },
                          [
                            i("label", { attrs: { for: "fontPreference" } }, [
                              t._v("Game Font"),
                            ]),
                            i(
                              "b-dropdown",
                              {
                                staticClass:
                                  "settings_modal_font_select_dropdown",
                                attrs: {
                                  "aria-role": "list",
                                  position: "is-top-left",
                                  value: t.fontPreference,
                                },
                                on: {
                                  change: function (e) {
                                    return t.setFont(e);
                                  },
                                },
                                scopedSlots: t._u(
                                  [
                                    {
                                      key: "trigger",
                                      fn: function (e) {
                                        e.active;
                                        return [
                                          i("b-button", {
                                            staticClass:
                                              "settings_modal_font_select_button",
                                            style: {
                                              "font-family":
                                                t.getFontFamilyFromKey(
                                                  t.fontPreference,
                                                ),
                                            },
                                            attrs: {
                                              label: t.getFontNameFromKey(
                                                t.fontPreference,
                                              ),
                                              type: "is-text",
                                            },
                                          }),
                                        ];
                                      },
                                    },
                                  ],
                                  null,
                                  !1,
                                  3510638343,
                                ),
                              },
                              t._l(t.fontOptions, function (e, n) {
                                return i(
                                  "b-dropdown-item",
                                  {
                                    key: n,
                                    style: {
                                      "font-family": t.getFontFamilyFromKey(n),
                                    },
                                    attrs: {
                                      "aria-role": "listitem",
                                      value: n,
                                    },
                                  },
                                  [t._v(" " + t._s(e) + " ")],
                                );
                              }),
                              1,
                            ),
                          ],
                          1,
                        )
                      : t._e(),
                    t.pause && t.lesson
                      ? i("div", { attrs: { id: "quitButton" } }, [
                          i(
                            "a",
                            {
                              attrs: { href: "#" },
                              on: {
                                click: function (e) {
                                  return (e.preventDefault(), t.quitLesson(e));
                                },
                              },
                            },
                            [
                              i("img", {
                                attrs: { src: "/images/quitButton.png" },
                              }),
                            ],
                          ),
                        ])
                      : t._e(),
                    t.pause && !t.lesson
                      ? i("div", { attrs: { id: "quitButton" } }, [
                          i(
                            "a",
                            {
                              attrs: { href: "#" },
                              on: {
                                click: function (e) {
                                  return (e.preventDefault(), t.quit(e));
                                },
                              },
                            },
                            [
                              i("img", {
                                attrs: { src: "/images/quitButton.png" },
                              }),
                            ],
                          ),
                        ])
                      : t._e(),
                  ]),
                ]),
              ]),
              i("button", {
                staticClass: "modal-close is-large",
                attrs: { "aria-label": "close" },
                on: {
                  click: function (e) {
                    return (e.preventDefault(), t.hideSettings(e));
                  },
                },
              }),
            ],
          );
        },
        s = [
          function () {
            var t = this,
              e = t.$createElement,
              i = t._self._c || e;
            return i("figure", { staticClass: "image is-4by3" }, [
              i("img", { attrs: { src: "/images/popup.png" } }),
            ]);
          },
          function () {
            var t = this,
              e = t.$createElement,
              i = t._self._c || e;
            return i("div", { attrs: { id: "title" } }, [
              i("figure", { staticClass: "image" }, [
                i("img", { attrs: { src: "/images/settings.png" } }),
              ]),
            ]);
          },
        ],
        r = (i(44114), i(13693)),
        o = i(7504),
        a = i(53235),
        l = i(43564),
        u = {
          name: "SettingsModal",
          mixins: [r.A, a.A],
          props: {
            pause: Boolean,
            number: Boolean,
            location: 0,
            ident: String,
            allowInvertCalculator: Boolean,
            lesson: { type: Boolean, default: !1 },
            hasCustomQuitHandler: { type: Boolean, default: !1 },
          },
          data() {
            return { config: o.A };
          },
          computed: {
            musicOn() {
              return this.$store.state.musicOn;
            },
            soundFXOn() {
              return this.$store.state.soundFXOn;
            },
            letterNamesOn() {
              return this.$store.state.letterNamesOn;
            },
            invertCalcOn() {
              return this.$store.state.invertCalcOn;
            },
            disableTimer() {
              return this.$store.state.disableTimer;
            },
            fontPreference() {
              return this.$store.state.fontPreference;
            },
            canChangeFont() {
              return this.$store.state.canChangeFont;
            },
            fontOptions() {
              const t = { dyslexic: "Open Dyslexic", muli: "Muli" };
              return (
                "en-us" === this.$i18n.locale
                  ? (t.sassoonUs = "Sassoon")
                  : "en-za" === this.$i18n.locale
                    ? (t.sassoonZa = "Sassoon")
                    : ((t.sassoon = "Sassoon"),
                      (t.sassoonCurly = "Sassoon Curly")),
                t
              );
            },
          },
          methods: {
            hideSettings() {
              this.$emit("hide");
            },
            getFontFamilyFromKey(t) {
              switch (t) {
                case "dyslexic":
                  return "OpenDyslexicAltaRegular";
                case "sassoon":
                  return "Sassoon";
                case "sassoonCurly":
                  return "SassoonCurly";
                case "sassoonUs":
                  return "SassoonUS";
                case "sassoonZa":
                  return "SassoonZA";
                case "muli":
                  return "Muli";
              }
            },
            getFontNameFromKey(t) {
              return this.fontOptions[t] || "Default";
            },
            quitLesson() {
              (this.$store.state.soundFXOn && this.$sounds.clickSound.play(),
                this.$emit("quit-episode"),
                this.$emit("hide"));
            },
            async quit() {
              if (
                (this.$store.state.soundFXOn && this.$sounds.clickSound.play(),
                this.hasCustomQuitHandler)
              )
                return void this.$emit("quit-handler");
              const t = await this.confirm({
                title: "Quit Game?",
                message: "Are you sure you want to quit this game?",
              });
              if (t)
                if ("quizshed" === this.location) {
                  const t = this.ident.charAt(0);
                  this.ident && "L" === t
                    ? (window.location.href =
                        this.config.serverInfo.quiz +
                        this.$i18n.locale +
                        "/lessons/" +
                        this.ident)
                    : this.ident && "Q" === t
                      ? (window.location.href =
                          this.config.serverInfo.quiz +
                          this.$i18n.locale +
                          "/browse/" +
                          this.ident)
                      : (window.location.href =
                          this.config.serverInfo.quiz +
                          this.$i18n.locale +
                          "/browse/");
                } else
                  "number" === this.location && this.$store.getters.hasNumber
                    ? this.$router.push({
                        name: "NumberMenu",
                        params: { lang: this.$i18n.locale },
                      })
                    : "spelling" === this.location &&
                        this.$store.getters.hasSpelling
                      ? this.$router.push({
                          name: "SpellingMenu",
                          params: { lang: this.$i18n.locale },
                        })
                      : "phonics" === this.location &&
                          this.$store.getters.hasSpelling
                        ? this.$router.push({
                            name: "Phonics Menu",
                            params: {
                              lang: this.$i18n.locale,
                              map_tab: this.$route.params.map_tab || "map",
                              grapheme: this.$route.params.grapheme || "",
                            },
                          })
                        : "assignments" === this.location
                          ? this.$router.push({
                              name: "Assignments",
                              params: { lang: this.$i18n.locale },
                            })
                          : null === this.location
                            ? this.$router.push({
                                name: "MainMenu",
                                params: { lang: this.$i18n.locale },
                              })
                            : this.$router.push({
                                name: "QuizMenu",
                                params: { lang: this.$i18n.locale },
                              });
            },
            async updateUserSetting(t, e) {
              await l.j.setSettings({ [t]: e });
            },
            toggleMusic() {
              const t = !this.musicOn;
              (this.$store.commit("SET_MUSIC", t),
                this.updateUserSetting("musicOn", t),
                t
                  ? ("unloaded" === this.$sounds.backgroundMusic.state() &&
                      this.$sounds.backgroundMusic.load(),
                    this.$sounds.backgroundMusic.play())
                  : this.$sounds.backgroundMusic.stop());
            },
            toggleSoundFX() {
              const t = !this.soundFXOn;
              (this.$store.commit("SET_SOUNDFX", t),
                this.updateUserSetting("soundFXOn", t),
                t &&
                  "unloaded" === this.$sounds.clickSound.state() &&
                  (this.$sounds.clickSound.load(),
                  this.$sounds.correctSound.load(),
                  this.$sounds.incorrectSound.load(),
                  this.$sounds.wellDoneSound.load()),
                this.$emit("setSoundFX", t));
            },
            toggleLetterNames() {
              const t = !this.letterNamesOn;
              (this.$store.commit("SET_LETTERNAMES", t),
                this.updateUserSetting("letterNamesOn", t));
            },
            toggleInvertCalc() {
              const t = !this.invertCalcOn;
              (this.$store.commit("SET_INVERTCALC", t),
                this.updateUserSetting("invertCalcOn", t));
            },
            toggleTimers() {
              const t = !this.disableTimer;
              (this.$store.commit("SET_DISABLE_TIMERS", t),
                this.updateUserSetting("disableTimer", t));
            },
            setFont(t) {
              (this.$store.commit("SET_FONT", t),
                this.updateUserSetting("fontPreference", t));
            },
          },
        },
        c = u,
        d = i(81656),
        f = (0, d.A)(c, n, s, !1, null, "155f7d83", null),
        h = f.exports;
    },
    93523: function (t, e, i) {
      "use strict";
      var n = i(31635),
        s = i(18657),
        r = i(40834),
        o = i(7504),
        a = i(27021);
      let l = class extends r.A {
        get _store() {
          return this.$store;
        }
        shuffleArray(t) {
          for (let e = t.length - 1; e > 0; e--) {
            const i = Math.floor(Math.random() * (e + 1)),
              n = t[e];
            ((t[e] = t[i]), (t[i] = n));
          }
          return t;
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
                PACKAGE_VERSION: "1.24.12",
              }.TARGET_ENV && !0
          );
        }
        randomString(t) {
          let e = "";
          const i = "abcdefghijklmnopqrstuvwxyz";
          for (let n = 0; n < t; n++)
            e += i.charAt(Math.floor(Math.random() * i.length));
          return e;
        }
        get config() {
          return o.A;
        }
        i18nLocaleFormat(t) {
          const e = t.split("-");
          return (e[1] && (e[1] = e[1].toUpperCase()), e.join("_"));
        }
        setUserData(t) {
          var e, i, n, s, r, o, a;
          if (!t) return;
          (this._store.commit("SET_USER", t),
            t.token && this._store.commit("SET_TOKEN", t.token),
            this._store.commit(
              "SET_MUSIC",
              !0 ===
                (null === (e = t.settings) || void 0 === e
                  ? void 0
                  : e.musicOn),
            ),
            this._store.commit(
              "SET_SOUNDFX",
              !0 ===
                (null === (i = t.settings) || void 0 === i
                  ? void 0
                  : i.soundFXOn),
            ),
            this._store.commit(
              "SET_LETTERNAMES",
              !0 ===
                (null === (n = t.settings) || void 0 === n
                  ? void 0
                  : n.letterNamesOn),
            ),
            this._store.commit(
              "SET_DISABLE_TIMERS",
              !0 ===
                (null === (s = t.settings) || void 0 === s
                  ? void 0
                  : s.disableTimer),
            ),
            this._store.commit(
              "SET_INVERTCALC",
              !0 ===
                (null === (r = t.settings) || void 0 === r
                  ? void 0
                  : r.invertCalcOn),
            ));
          const l = t.school,
            u =
              void 0 === l ||
              1 === l.teacher ||
              1 === l.admin ||
              null ===
                (null === (o = l.settings) || void 0 === o
                  ? void 0
                  : o.fontPreference) ||
              void 0 ===
                (null === (a = l.settings) || void 0 === a
                  ? void 0
                  : a.fontPreference);
          this._store.commit("SET_CAN_CHANGE_FONT", u);
          let c = "sassoon";
          switch (t.locale) {
            case "en_US":
              c = "sassoonUs";
              break;
            case "en_ZA":
              c = "sassoonZa";
              break;
            default:
              c = "sassoon";
              break;
          }
          var d, f, h;
          u
            ? (c =
                (null === (d = t.settings) || void 0 === d
                  ? void 0
                  : d.fontPreference) ||
                (null === l ||
                void 0 === l ||
                null === (f = l.settings) ||
                void 0 === f
                  ? void 0
                  : f.fontPreference) ||
                c)
            : (c =
                (null === l ||
                void 0 === l ||
                null === (h = l.settings) ||
                void 0 === h
                  ? void 0
                  : h.fontPreference) || c);
          this._store.commit("SET_FONT", c);
        }
        async logError(t, e, i, n) {
          try {
            var s, r;
            const o = {
              clientTimestamp: Date.now(),
              data: null !== e && void 0 !== e ? e : {},
              key: null !== i && void 0 !== i ? i : "",
              message: t.message,
              trace: null !== (s = t.stack) && void 0 !== s ? s : "",
              userId:
                null === (r = this._store.state.user) || void 0 === r
                  ? void 0
                  : r.id,
              logGroup: "play",
              errorRef: n,
            };
            (console.log(o), await a.jIY.logClientError(o));
          } catch (o) {
            console.error("failed to log error", o);
          }
        }
      };
      ((l = (0, n.Cg)([s.uA], l)), (e.A = l));
    },
  },
]);
//# sourceMappingURL=764.aa236225.js.map
