"use strict";
(self["webpackChunkgame"] = self["webpackChunkgame"] || []).push([
  [4967],
  {
    28939: function (t, e, s) {
      s.d(e, {
        A: function () {
          return c;
        },
      });
      var r = function () {
          var t = this,
            e = t.$createElement,
            s = t._self._c || e;
          return s("div", { staticClass: "timerBar" }, [
            s("div", {
              staticClass: "innerBar is-pulled-right",
              style: "width:" + 100 * t.full + "%",
            }),
          ]);
        },
        a = [],
        i = { name: "TimerBar", props: ["full"] },
        n = i,
        o = s(81656),
        l = (0, o.A)(n, r, a, !1, null, null, null),
        c = l.exports;
    },
    47236: function (t, e, s) {
      s.d(e, {
        A: function () {
          return N;
        },
      });
      var r = function () {
          var t = this,
            e = t.$createElement,
            s = t._self._c || e;
          return s(
            "div",
            {
              class: { red: t.red, msg: t.message, small: t.small },
              attrs: { id: "bottomBar" },
            },
            [
              s("div", { staticClass: "container" }, [
                s("div", { staticClass: "columns is-mobile is-gapless" }, [
                  s(
                    "div",
                    {
                      staticClass: "column",
                      class: {
                        "is-3": !t.canSkip,
                        "is-3-desktop": t.canSkip,
                        "is-5-mobile": t.canSkip,
                        "is-3-tablet": t.canSkip,
                      },
                    },
                    [
                      t.streakMultiplier > 1 && t.showStreak && !t.canSkip
                        ? s("StreakIndicator", {
                            attrs: { multiplier: t.streakMultiplier },
                          })
                        : t._e(),
                    ],
                    1,
                  ),
                  s(
                    "div",
                    {
                      class: {
                        column: !0,
                        "is-7": !t.small && !t.canSkip,
                        "is-7-desktop": !t.small && t.canSkip,
                        "is-7-tablet": !t.small && t.canSkip,
                        "is-9-mobile": t.small,
                        "is-7-tablet": t.small,
                        "is-5-mobile": t.canSkip,
                      },
                    },
                    [
                      t.showProgress
                        ? s("ProgressBar", {
                            attrs: {
                              "word-index": t.showCorrectCount
                                ? t.correctIndex
                                : t.wordIndex,
                              total: t.totalWords,
                              "is-correct-index": t.showCorrectCount,
                            },
                          })
                        : t._e(),
                      t.showScore
                        ? s("ScoreBar", { attrs: { score: t.score } })
                        : t._e(),
                      t.canSkip && t.showTick
                        ? s(
                            "SlickButton",
                            {
                              attrs: {
                                id: "skipButton",
                                type: "skip",
                                color: "yellow",
                                tabindex: "-1",
                              },
                              on: {
                                click: function (e) {
                                  return (
                                    e.preventDefault(),
                                    t.skipButtonAction(e)
                                  );
                                },
                                keydown: function (e) {
                                  if (
                                    !e.type.indexOf("key") &&
                                    t._k(e.keyCode, "enter", 13, e.key, "Enter")
                                  )
                                    return null;
                                  e.preventDefault();
                                },
                              },
                            },
                            [t._v(" I Don't Know ")],
                          )
                        : t._e(),
                    ],
                    1,
                  ),
                  t.small
                    ? t._e()
                    : s(
                        "div",
                        { staticClass: "column is-2" },
                        [
                          t.showTick
                            ? s("SlickButton", {
                                attrs: {
                                  id: "tickButton",
                                  type: "submit",
                                  tabindex: "-1",
                                },
                                on: {
                                  click: function (e) {
                                    return (
                                      e.preventDefault(),
                                      t.tickButtonAction(e)
                                    );
                                  },
                                  keydown: function (e) {
                                    if (
                                      !e.type.indexOf("key") &&
                                      t._k(
                                        e.keyCode,
                                        "enter",
                                        13,
                                        e.key,
                                        "Enter",
                                      )
                                    )
                                      return null;
                                    e.preventDefault();
                                  },
                                },
                              })
                            : t._e(),
                        ],
                        1,
                      ),
                ]),
              ]),
              t.message
                ? s("div", { staticClass: "messageBar" }, [
                    t._v(" " + t._s(t.message) + " "),
                  ])
                : t._e(),
            ],
          );
        },
        a = [],
        i = function () {
          var t = this,
            e = t.$createElement,
            s = t._self._c || e;
          return s(
            "figure",
            { staticClass: "image", attrs: { id: "streakIndicator" } },
            [
              s("img", { attrs: { src: "/images/streakIndicator.png" } }),
              s("p", { attrs: { id: "streakScore" } }, [
                t._v(" x" + t._s(t.multiplier) + " "),
              ]),
            ],
          );
        },
        n = [],
        o = {
          name: "StreakIndicator",
          props: ["multiplier"],
          data() {
            return {};
          },
        },
        l = o,
        c = s(81656),
        u = (0, c.A)(l, i, n, !1, null, "31d54684", null),
        d = u.exports,
        p = function () {
          var t = this,
            e = t.$createElement,
            s = t._self._c || e;
          return s(
            "figure",
            {
              staticClass: "image is-pulled-right",
              attrs: { id: "progressBar" },
            },
            [
              s("div", {
                style: "width:" + t.progressPercentage + "%",
                attrs: { id: "progressTopBar" },
              }),
              s("img", {
                staticClass: "backgroundBar",
                attrs: { src: "/images/scoreBar.png" },
              }),
              s("p", { attrs: { id: "progress" } }, [
                t._v(" " + t._s(t.progressText) + " "),
              ]),
            ],
          );
        },
        m = [],
        k = {
          name: "ProgressBar",
          props: ["wordIndex", "total", "isCorrectIndex"],
          data() {
            return {};
          },
          computed: {
            progressPercentage() {
              let t = 0;
              return (
                0 !== this.total &&
                  null !== this.total &&
                  (t = Math.min(100, (100 * this.progressIndex) / this.total)),
                t
              );
            },
            progressIndex() {
              return this.isCorrectIndex ? this.wordIndex : this.wordIndex + 1;
            },
            progressText() {
              return null === this.total
                ? this.progressIndex
                : this.progressIndex + "/" + this.total;
            },
          },
        },
        f = k,
        g = (0, c.A)(f, p, m, !1, null, "70f6c307", null),
        h = g.exports,
        _ = function () {
          var t = this,
            e = t.$createElement,
            s = t._self._c || e;
          return s(
            "figure",
            { staticClass: "image is-pulled-right", attrs: { id: "scoreBar" } },
            [
              s("img", { attrs: { src: "/images/scoreBar.png" } }),
              s("p", { attrs: { id: "score" } }, [
                t._v(" " + t._s(t.enforceLatinNumberSystem(t.score)) + " "),
              ]),
            ],
          );
        },
        v = [],
        x = s(22735),
        C = {
          name: "ScoreBar",
          props: ["score"],
          data() {
            return {};
          },
          methods: { enforceLatinNumberSystem: x.xE },
        },
        y = C,
        b = (0, c.A)(y, _, v, !1, null, "6073f063", null),
        w = b.exports,
        B = function () {
          var t = this,
            e = t.$createElement,
            s = t._self._c || e;
          return s(
            "button",
            {
              staticClass: "slick-button",
              class:
                "color-" +
                (t.color || "green") +
                " type-" +
                (t.type || "normal"),
              attrs: { disabled: t.disabled },
              on: { click: t.onButtonClick },
            },
            [
              "skip" === t.type
                ? s("span", { staticClass: "slick-button__skip" }, [
                    s(
                      "svg",
                      {
                        attrs: {
                          id: "uuid-1f8d989e-f6e9-4310-b044-900168cc4a7b",
                          xmlns: "http://www.w3.org/2000/svg",
                          viewBox: "0 0 138.06 30.18",
                        },
                      },
                      [
                        s(
                          "g",
                          {
                            attrs: {
                              id: "uuid-7f5b20e3-b616-4973-a0d7-014278391b67",
                            },
                          },
                          [
                            s("path", {
                              staticStyle: { fill: "#fff" },
                              attrs: {
                                d: "M129.51,.19l-.58,17.38C95.48-7.98,28.21-5.41,.82,23.61c-1.14,1.21-1.08,3.1,.12,4.24,.58,.55,1.32,.82,2.06,.82,.8,0,1.59-.32,2.18-.94C17.26,14.93,39.62,6.82,64.99,6.05c22.72-.69,43.91,4.77,58.27,14.8l-15.31-.52,8.55,9.15,20.85,.7,.7-20.85L129.51,.19Z",
                              },
                            }),
                          ],
                        ),
                      ],
                    ),
                  ])
                : t._e(),
              "submit" === t.type
                ? s("span", { staticClass: "slick-button__submit" }, [
                    s(
                      "svg",
                      {
                        attrs: {
                          id: "uuid-635f5c66-2b9a-49fd-90a3-82061f0fabd0",
                          xmlns: "http://www.w3.org/2000/svg",
                          viewBox: "0 0 56.41 54.55",
                        },
                      },
                      [
                        s(
                          "g",
                          {
                            attrs: {
                              id: "uuid-cfd77cc2-bd77-4df7-8f52-28f713397535",
                            },
                          },
                          [
                            s("path", {
                              staticStyle: { fill: "#fff" },
                              attrs: {
                                d: "M1.19,29.68c7.79,1.93,14.45,7.28,19.78,13.15,0,0-6.89,.58-6.89,.58C23.43,25.85,36.62,9.26,54.62,.14c1.36-.68,2.53,1.29,1.21,2.14-8.13,5.16-15.03,11.98-20.68,19.63-7.36,9.76-12.5,21.34-17.08,32.64-2.66-5.16-5.65-11.71-9.41-16.11-2.27-2.75-4.97-5.17-8.16-6.97-.98-.53-.38-2.07,.7-1.79h0Z",
                              },
                            }),
                          ],
                        ),
                      ],
                    ),
                  ])
                : t._e(),
              "submit" !== t.type
                ? s("span", { staticClass: "slot" }, [t._t("default")], 2)
                : t._e(),
            ],
          );
        },
        S = [],
        A = s(91114),
        E = (s(62953), s(31635)),
        I = s(18657);
      let $ = class extends (0, I.Xe)() {
        constructor(...t) {
          (super(...t),
            (0, A.A)(this, "disabled", void 0),
            (0, A.A)(this, "color", void 0),
            (0, A.A)(this, "type", void 0));
        }
        onButtonClick(t) {
          this.disabled || this.$emit("click", t);
        }
      };
      ((0, E.Cg)([(0, I.kv)({ default: !1 })], $.prototype, "disabled", void 0),
        (0, E.Cg)(
          [(0, I.kv)({ default: "green" })],
          $.prototype,
          "color",
          void 0,
        ),
        (0, E.Cg)([(0, I.kv)({ default: "" })], $.prototype, "type", void 0),
        ($ = (0, E.Cg)([I.uA], $)));
      var T = $,
        D = T,
        P = (0, c.A)(D, B, S, !1, null, "70d51d6c", null),
        G = P.exports,
        M = {
          name: "BottomBar",
          components: {
            StreakIndicator: d,
            ProgressBar: h,
            ScoreBar: w,
            SlickButton: G,
          },
          props: [
            "wordIndex",
            "totalWords",
            "streakMultiplier",
            "score",
            "showTick",
            "showProgress",
            "showScore",
            "showStreak",
            "red",
            "message",
            "small",
            "showCorrectCount",
            "correctIndex",
            "canSkip",
          ],
          data() {
            return {};
          },
          methods: {
            tickButtonAction(t) {
              (t.target && t.target.blur(), this.$emit("tick"));
            },
            skipButtonAction(t) {
              (t.target && t.target.blur(), this.$emit("skip"));
            },
          },
        },
        O = M,
        L = (0, c.A)(O, r, a, !1, null, "855cdec6", null),
        N = L.exports;
    },
    51622: function (t, e, s) {
      s.d(e, {
        A: function () {
          return u;
        },
      });
      var r = function () {
          var t = this,
            e = t.$createElement,
            s = t._self._c || e;
          return s("div", { attrs: { id: "topBar" } }, [
            s("div", { staticClass: "container" }, [
              s("div", { staticClass: "columns is-mobile is-gapless" }, [
                s("div", { staticClass: "column is-2" }, [
                  t.showSayWord
                    ? s(
                        "a",
                        {
                          staticClass: "image is-pulled-right",
                          attrs: { tabindex: "-1", href: "#" },
                          on: {
                            keydown: function (e) {
                              if (
                                !e.type.indexOf("key") &&
                                t._k(e.keyCode, "enter", 13, e.key, "Enter")
                              )
                                return null;
                              e.preventDefault();
                            },
                            click: function (e) {
                              return (
                                e.preventDefault(),
                                t.playAudioButtonAction(e)
                              );
                            },
                          },
                        },
                        [t._m(0)],
                      )
                    : t._e(),
                  t.showScore
                    ? s(
                        "span",
                        {
                          staticClass: "tag is-large is-pulled-right scoreText",
                        },
                        [t._v("🍯 " + t._s(t.score))],
                      )
                    : t._e(),
                  !t.showNumberScore ||
                  (null == t.score && null == t.answersGiven)
                    ? t._e()
                    : s(
                        "span",
                        {
                          staticClass: "tag is-numberScore is-large scoreText",
                        },
                        [
                          null != t.score
                            ? s("span", [
                                s("i", { staticClass: "emojiIcon emojiStar" }),
                                t._v(
                                  " " +
                                    t._s(t.enforceLatinNumberSystem(t.score)),
                                ),
                              ])
                            : t._e(),
                          null != t.answersGiven
                            ? s(
                                "span",
                                {
                                  style:
                                    null != t.score ? "margin-left: 15px" : "",
                                },
                                [
                                  t._v(
                                    "✅ " +
                                      t._s(
                                        t.answersGiven.filter(function (t) {
                                          return 1 == t.correct;
                                        }).length,
                                      ) +
                                      " / " +
                                      t._s(t.answersGiven.length),
                                  ),
                                ],
                              )
                            : t._e(),
                        ],
                      ),
                  t.streak
                    ? s(
                        "span",
                        {
                          staticClass: "tag is-streak-text is-large scoreText",
                          staticStyle: { "z-index": "1", position: "relative" },
                        },
                        [t._v("🔥 " + t._s(t.streak))],
                      )
                    : t._e(),
                ]),
                s(
                  "div",
                  { staticClass: "column", attrs: { id: "textBoxColumn" } },
                  [
                    t.showTextBar
                      ? s(
                          "p",
                          { staticClass: "input", attrs: { id: "textBox" } },
                          [
                            t._v(" " + t._s(t.barText)),
                            s(
                              "span",
                              {
                                class:
                                  "cursor" +
                                  (t.lastCharSpace ? " leftMargin" : ""),
                              },
                              [t._v("|")],
                            ),
                            t._v(" "),
                            s(
                              "a",
                              {
                                staticClass: "is-pulled-right has-text-right",
                                attrs: {
                                  id: "backspaceButton",
                                  tabindex: "-1",
                                  href: "#",
                                },
                                on: {
                                  keydown: function (e) {
                                    if (
                                      !e.type.indexOf("key") &&
                                      t._k(
                                        e.keyCode,
                                        "enter",
                                        13,
                                        e.key,
                                        "Enter",
                                      )
                                    )
                                      return null;
                                    e.preventDefault();
                                  },
                                  click: function (e) {
                                    return (
                                      e.preventDefault(),
                                      t.backspaceButtonAction(e)
                                    );
                                  },
                                },
                              },
                              [t._m(1)],
                            ),
                          ],
                        )
                      : t.streak
                        ? s("div", { staticClass: "streakContainer" }, [
                            s(
                              "div",
                              {
                                staticClass: "is-flex",
                                staticStyle: {
                                  width: "fit:content",
                                  "justify-self": "flex-end",
                                  "flex-direction": "row",
                                  position: "absolute",
                                  right: "0",
                                  top: "0",
                                },
                              },
                              t._l(t.streak, function (e) {
                                return s(
                                  "figure",
                                  {
                                    key: e,
                                    staticClass: "is-flex",
                                    staticStyle: {
                                      "justify-content": "flex-end",
                                      "margin-top": "auto",
                                    },
                                  },
                                  [
                                    s("img", {
                                      staticClass: "checkImage",
                                      attrs: {
                                        src:
                                          e === t.streakMax
                                            ? "/images/checkStar.png"
                                            : e % 10
                                              ? e < t.streakBreaks[0]
                                                ? "/images/check.png"
                                                : e < t.streakBreaks[1]
                                                  ? "/images/checkFire1.png"
                                                  : e < t.streakBreaks[2]
                                                    ? "/images/checkFire2.png"
                                                    : "/images/checkFire3.png"
                                              : "/images/checkPink.png",
                                      },
                                    }),
                                  ],
                                );
                              }),
                              0,
                            ),
                          ])
                        : t._e(),
                  ],
                ),
                s("div", { staticClass: "column is-2" }, [
                  t.showEndGame
                    ? s(
                        "a",
                        {
                          staticClass: "is-inline-block",
                          attrs: { tabindex: "-1", href: "#" },
                          on: {
                            keydown: function (e) {
                              if (
                                !e.type.indexOf("key") &&
                                t._k(e.keyCode, "enter", 13, e.key, "Enter")
                              )
                                return null;
                              e.preventDefault();
                            },
                            click: function (e) {
                              return (e.preventDefault(), t.endGame(e));
                            },
                          },
                        },
                        [t._m(2)],
                      )
                    : t._e(),
                  t.hidePause
                    ? t._e()
                    : s(
                        "a",
                        {
                          staticClass: "is-inline-block",
                          attrs: { tabindex: "-1", href: "#" },
                          on: {
                            keydown: function (e) {
                              if (
                                !e.type.indexOf("key") &&
                                t._k(e.keyCode, "enter", 13, e.key, "Enter")
                              )
                                return null;
                              e.preventDefault();
                            },
                            click: function (e) {
                              return (
                                e.preventDefault(),
                                t.pauseButtonAction(e)
                              );
                            },
                          },
                        },
                        [t._m(3)],
                      ),
                ]),
              ]),
            ]),
          ]);
        },
        a = [
          function () {
            var t = this,
              e = t.$createElement,
              s = t._self._c || e;
            return s("figure", { attrs: { id: "playAudioButton" } }, [
              s("img", { attrs: { src: "/images/playAudioButton.png" } }),
            ]);
          },
          function () {
            var t = this,
              e = t.$createElement,
              s = t._self._c || e;
            return s("figure", { staticClass: "is-pulled-right" }, [
              s("img", { attrs: { src: "/images/backspaceButton.png" } }),
            ]);
          },
          function () {
            var t = this,
              e = t.$createElement,
              s = t._self._c || e;
            return s(
              "figure",
              { staticClass: "image", attrs: { id: "endButton" } },
              [s("img", { attrs: { src: "/images/CalcButton.png" } })],
            );
          },
          function () {
            var t = this,
              e = t.$createElement,
              s = t._self._c || e;
            return s(
              "figure",
              { staticClass: "image", attrs: { id: "pauseButton" } },
              [s("img", { attrs: { src: "/images/pauseButton.png" } })],
            );
          },
        ],
        i = s(22735),
        n = {
          name: "TopBar",
          props: [
            "barText",
            "showTextBar",
            "showSayWord",
            "score",
            "showScore",
            "showNumberScore",
            "answersGiven",
            "hidePause",
            "streak",
            "streakMax",
            "streakBreaks",
            "showEndGame",
          ],
          data() {
            return {};
          },
          computed: {
            lastCharSpace() {
              return " " === this.barText[this.barText.length - 1];
            },
          },
          methods: {
            backspaceButtonAction() {
              (console.log("BACKSPACE"), this.$emit("backspace"));
            },
            playAudioButtonAction() {
              (console.log("PLAY AUDIO"), this.$emit("sayword"));
            },
            pauseButtonAction() {
              (console.log("PAUSE"), this.$emit("pause"));
            },
            endGame() {
              this.$emit("endgame");
            },
            enforceLatinNumberSystem: i.xE,
          },
        },
        o = n,
        l = s(81656),
        c = (0, l.A)(o, r, a, !1, null, "1521293a", null),
        u = c.exports;
    },
  },
]);
//# sourceMappingURL=4967.f7eb365d.js.map
